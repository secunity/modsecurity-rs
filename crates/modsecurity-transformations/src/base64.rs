//! Base64 encoding and decoding, strict (mbedtls) and forgiving.
//!
//! Encoding is standard base64 with `=` padding: the `base64` crate gives
//! what `mbedtls_base64_encode` gives. The strict decoder follows
//! `mbedtls_base64_decode`, which the original ModSecurity calls: its
//! exact semantics (which whitespace is tolerated, how padding is
//! validated, ...) are observable through `t:base64Decode`, the tests of
//! the original ModSecurity depend on them, and the `base64` crate decides
//! otherwise, so it is written out here (`mbedtls_decode`, after mbedtls
//! `base64.c`). The forgiving decoder ([`Base64::decode_forgiven`]) is
//! ModSecurity's own algorithm.

/// Base64 encoding and decoding.
#[derive(Debug, Clone, Copy, Default)]
pub struct Base64;

/// `mbedtls_ct_base64_dec_value`: the value of a base64 digit.
#[inline]
fn mbedtls_dec_value(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// The value of a digit for the forgiving decoder: the standard alphabet
/// and the URL-safe one (`-` and `_`).
#[inline]
fn forgiving_digit(c: u8) -> Option<u8> {
    match c {
        b'-' => Some(62),
        b'_' => Some(63),
        _ => mbedtls_dec_value(c),
    }
}

/// Decodes `src` as `mbedtls_base64_decode` does: `None` on
/// `MBEDTLS_ERR_BASE64_INVALID_CHARACTER`.
fn mbedtls_decode(src: &[u8]) -> Option<Vec<u8>> {
    let slen = src.len();
    let mut equals = 0usize;
    let mut n = 0usize; // number of digits or trailing = in source

    // First pass: check for validity and get output length.
    let mut i = 0usize;
    while i < slen {
        // Skip spaces before checking for EOL.
        let mut spaces_present = false;
        while i < slen && src[i] == b' ' {
            i += 1;
            spaces_present = true;
        }

        // Spaces at end of buffer are OK.
        if i == slen {
            break;
        }

        if (slen - i) >= 2 && src[i] == b'\r' && src[i + 1] == b'\n' {
            i += 1;
            continue;
        }

        if src[i] == b'\n' {
            i += 1;
            continue;
        }

        // Space inside a line is an error.
        if spaces_present {
            return None;
        }

        if src[i] > 127 {
            return None;
        }

        if src[i] == b'=' {
            equals += 1;
            if equals > 2 {
                return None;
            }
        } else {
            if equals != 0 {
                return None;
            }
            // Anything else must be a digit.
            mbedtls_dec_value(src[i])?;
        }
        n += 1;
        i += 1;
    }

    // In valid base64, the number of digits (n-equals) is always of the form
    // 4*k, 4*k+2 or *4k+3. Also, the number n of digits plus the number of
    // equal signs at the end is always a multiple of 4.
    if (n - equals) % 4 == 1 {
        return None;
    }
    if !n.is_multiple_of(4) {
        return None;
    }

    let olen = (n / 4) * 3 - equals;
    let mut out = Vec::with_capacity(olen);

    // Second pass over the `i` bytes examined by the first one.
    let mut x: u32 = 0;
    let mut accumulated_digits = 0u32;
    for &c in &src[..i] {
        if c == b'=' {
            // We already know from the first loop that equal signs are
            // only at the end.
            break;
        }
        // The first pass let only digits and line breaks through.
        let Some(value) = mbedtls_dec_value(c) else {
            continue;
        };
        x = (x << 6) | u32::from(value);
        accumulated_digits += 1;
        if accumulated_digits == 4 {
            accumulated_digits = 0;
            out.push((x >> 16) as u8);
            out.push((x >> 8) as u8);
            out.push(x as u8);
        }
    }
    if accumulated_digits == 3 {
        let x = x << 6;
        out.push((x >> 16) as u8);
        out.push((x >> 8) as u8);
    } else if accumulated_digits == 2 {
        let x = x << 12;
        out.push((x >> 16) as u8);
    }

    // mbedtls returns MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED here; it cannot
    // happen once the first pass validated the input.
    if out.len() != olen {
        return None;
    }
    Some(out)
}

impl Base64 {
    /// Standard base64 with `=` padding, as `mbedtls_base64_encode`
    /// gives it (the `base64` crate). Encoding cannot fail.
    pub fn encode(data: &[u8]) -> Vec<u8> {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(data).into_bytes()
    }

    /// Strict (mbedtls) decoding; `None` when the input is not valid
    /// base64. Spaces at line ends and `\n` / `\r\n` line breaks are
    /// accepted.
    ///
    /// The input stops at the first NUL byte: the original ModSecurity
    /// reads it as a C string, and its tests depend on that.
    pub fn decode(data: &[u8]) -> Option<Vec<u8>> {
        mbedtls_decode(modsecurity_compat::chars::c_str(data))
    }

    /// Lenient decoding (`t:base64DecodeExt`): bytes that are not digits
    /// (of the standard or the URL-safe alphabet) are skipped, and so is
    /// padding. Invalid input decodes to an empty value: a `=` after a
    /// lone digit of a group (unless another `=` follows it), or a value
    /// that ends with one.
    ///
    /// A final `9` counts as a final `=`: the original algorithm compares
    /// the decoded value of the last digit (61 for `9`) with the code of
    /// `=` (61).
    pub fn decode_forgiven(data: &[u8]) -> Vec<u8> {
        const PAD: u8 = b'=';
        let mut out = Vec::with_capacity(data.len() / 4 * 3 + 2);
        let mut digits = 0usize;
        // The high bits of the byte being decoded.
        let mut partial = 0u8;
        let mut ends_with_padding = false;
        for (pos, &c) in data.iter().enumerate() {
            if c == PAD {
                if digits % 4 == 1 && data.get(pos + 1) != Some(&PAD) {
                    return Vec::new();
                }
                ends_with_padding = true;
                continue;
            }
            let Some(value) = forgiving_digit(c) else {
                ends_with_padding = false;
                continue;
            };
            ends_with_padding = value == PAD;
            match digits % 4 {
                0 => partial = value << 2,
                1 => {
                    out.push(partial | value >> 4);
                    partial = (value & 0x0f) << 4;
                }
                2 => {
                    out.push(partial | value >> 2);
                    partial = (value & 0x03) << 6;
                }
                _ => out.push(partial | value),
            }
            digits += 1;
        }
        if ends_with_padding && digits % 4 == 1 {
            return Vec::new();
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_padding() {
        assert_eq!(Base64::encode(b""), b"");
        assert_eq!(Base64::encode(b"f"), b"Zg==");
        assert_eq!(Base64::encode(b"fo"), b"Zm8=");
        assert_eq!(Base64::encode(b"foo"), b"Zm9v");
        assert_eq!(Base64::encode(b"\xff\xfe\xfd\xfc"), b"//79/A==");
    }

    #[test]
    fn strict_decode() {
        assert_eq!(Base64::decode(b"Zm9vYmFy").unwrap(), b"foobar");
        assert_eq!(Base64::decode(b"Zm9vYg==").unwrap(), b"foob");
        assert_eq!(Base64::decode(b"Zm9vYmE=").unwrap(), b"fooba");
        // line breaks and trailing spaces are accepted
        assert_eq!(Base64::decode(b"Zm9v\r\nYmFy  ").unwrap(), b"foobar");
        assert_eq!(Base64::decode(b"Zm9v  \nYmFy").unwrap(), b"foobar");
        // only spaces: empty output
        assert_eq!(Base64::decode(b"   ").unwrap(), b"");
        // stops at NUL
        assert_eq!(Base64::decode(b"Zm9v\0garbage").unwrap(), b"foo");
        // invalid inputs
        assert!(Base64::decode(b"Zm9").is_none());
        assert!(Base64::decode(b"Zm 9v").is_none());
        assert!(Base64::decode(b"Zm9vY===").is_none());
        assert!(Base64::decode(b"Zm=v").is_none());
        assert!(Base64::decode(b"Zm9v\r").is_none());
        assert!(Base64::decode(b"Zm9-").is_none());
    }

    #[test]
    fn forgiven_decode() {
        assert_eq!(Base64::decode_forgiven(b"Zm9vYmFy"), b"foobar");
        assert_eq!(Base64::decode_forgiven(b"Zm9vYg"), b"foob");
        assert_eq!(Base64::decode_forgiven(b"Zm9v.YmFy"), b"foobar");
        assert_eq!(Base64::decode_forgiven(b"-_8="), b"\xfb\xff");
        // a lone digit followed by padding is invalid -> empty
        assert_eq!(Base64::decode_forgiven(b"Zm9vY="), b"");
        assert_eq!(Base64::decode_forgiven(b""), b"");
        // A final 9 is taken as padding.
        assert_eq!(Base64::decode_forgiven(b"Zm9v9"), b"");
        assert_eq!(Base64::decode_forgiven(b"Zm9vA9"), b"foo\x03");
    }
}
