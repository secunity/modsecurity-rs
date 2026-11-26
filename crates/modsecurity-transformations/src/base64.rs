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
///
/// What it accepts, line by line (lines end with `\n` or `\r\n`):
/// digits, then at most two `=` in all, which only line breaks and
/// spaces may follow; spaces only at the end of a line. The digits and
/// the `=` together are a multiple of 4.
fn mbedtls_decode(src: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(src.len() / 4 * 3);
    // The last digits read, 6 bits each; a full group of 4 is written out.
    let mut group: u32 = 0;
    let mut digits = 0usize;
    let mut padding = 0usize;
    for line in src.split_inclusive(|&c| c == b'\n') {
        let line = match line.strip_suffix(b"\n") {
            Some(line) => line.strip_suffix(b"\r").unwrap_or(line),
            None => line,
        };
        // Spaces at the end of a line are allowed (and only there).
        let digits_end = line.iter().rposition(|&c| c != b' ').map_or(0, |last| last + 1);
        for &c in &line[..digits_end] {
            if c == b'=' {
                padding += 1;
                if padding > 2 {
                    return None;
                }
                continue;
            }
            if padding > 0 {
                return None;
            }
            group = group << 6 | u32::from(mbedtls_dec_value(c)?);
            digits += 1;
            if digits.is_multiple_of(4) {
                out.extend_from_slice(&group.to_be_bytes()[1..]);
            }
        }
    }
    if !(digits + padding).is_multiple_of(4) {
        return None;
    }
    // With at most two `=`, an incomplete group has 2 or 3 digits: 1 or 2
    // bytes.
    match digits % 4 {
        2 => out.push((group << 12).to_be_bytes()[1]),
        3 => out.extend_from_slice(&(group << 6).to_be_bytes()[1..3]),
        _ => {}
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
