//! Port of `src/utils/base64.cc`, `src/utils/base64.h`.
//!
//! The C++ code delegates the strict encoder/decoder to mbedtls
//! (`mbedtls_base64_encode` / `mbedtls_base64_decode`). Their exact semantics
//! (which whitespace is tolerated, how padding is validated, ...) are
//! observable through `t:base64Decode`, so they are hand-ported here
//! (`mbedtls_encode` / `mbedtls_decode`, from mbedtls `base64.c`) instead of
//! using a different base64 implementation. The forgiving decoder
//! (`decode_forgiven_engine`) is ModSecurity's own code.

/// `Utils::Base64`
#[derive(Debug, Clone, Copy, Default)]
pub struct Base64;

/// Standard base64 alphabet (`mbedtls_ct_base64_enc_char`).
const ENC_TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// `mbedtls_ct_base64_dec_value`: value of a base64 digit, or -1.
#[inline]
fn mbedtls_dec_value(c: u8) -> i8 {
    match c {
        b'A'..=b'Z' => (c - b'A') as i8,
        b'a'..=b'z' => (c - b'a' + 26) as i8,
        b'0'..=b'9' => (c - b'0' + 52) as i8,
        b'+' => 62,
        b'/' => 63,
        _ => -1,
    }
}

/// `mbedtls_base64_encode` (with the output buffer sized by the
/// `base64HelperMbedtls` sizing call).
fn mbedtls_encode(src: &[u8]) -> Vec<u8> {
    let slen = src.len();
    if slen == 0 {
        return Vec::new();
    }
    let n = (slen / 3 + usize::from(!slen.is_multiple_of(3))) * 4;
    let mut out = Vec::with_capacity(n);
    let enc = |v: u32| ENC_TABLE[(v & 0x3F) as usize];

    let full = (slen / 3) * 3;
    let mut i = 0;
    while i < full {
        let c1 = u32::from(src[i]);
        let c2 = u32::from(src[i + 1]);
        let c3 = u32::from(src[i + 2]);
        out.push(enc(c1 >> 2));
        out.push(enc(((c1 & 3) << 4) + (c2 >> 4)));
        out.push(enc(((c2 & 15) << 2) + (c3 >> 6)));
        out.push(enc(c3));
        i += 3;
    }

    if i < slen {
        let c1 = u32::from(src[i]);
        let c2 = if i + 1 < slen { u32::from(src[i + 1]) } else { 0 };
        out.push(enc(c1 >> 2));
        out.push(enc(((c1 & 3) << 4) + (c2 >> 4)));
        if i + 1 < slen {
            out.push(enc((c2 & 15) << 2));
        } else {
            out.push(b'=');
        }
        out.push(b'=');
    }
    out
}

/// `mbedtls_base64_decode`: `None` on `MBEDTLS_ERR_BASE64_INVALID_CHARACTER`.
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
            if mbedtls_dec_value(src[i]) < 0 {
                return None;
            }
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
        if c == b'\r' || c == b'\n' || c == b' ' {
            continue;
        }
        if c == b'=' {
            // We already know from the first loop that equal signs are
            // only at the end.
            break;
        }
        x = (x << 6) | u32::from(mbedtls_dec_value(c) as u8);
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

/// `b64_reverse_t` of `decode_forgiven_engine`: -1 for skipped whitespace,
/// -2 for invalid characters (both are ignored), otherwise the digit value.
/// Both `+`/`-` map to 62 and both `/`/`_` map to 63 (URL-safe alphabet).
#[rustfmt::skip]
static B64_REVERSE_T: [i32; 256] = [
    -2, -2, -2, -2, -2, -2, -2, -2, -2, -1, -1, -2, -2, -1, -2, -2,
    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
    -1, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, 62, -2, 62, -2, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -2, -2, -2, -2, -2, -2,
    -2, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -2, -2, -2, -2, 63,
    -2, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
];

impl Base64 {
    /// `Base64::encode`: standard base64 with `=` padding. (The C++ version
    /// can only fail on a null output pointer or a size overflow, so this
    /// one is infallible.)
    pub fn encode(data: &[u8]) -> Vec<u8> {
        mbedtls_encode(data)
    }

    /// `Base64::decode(data, output, forgiven)`.
    pub fn decode_with(data: &[u8], forgiven: bool) -> Option<Vec<u8>> {
        if forgiven {
            return Self::decode_forgiven(data);
        }
        Self::decode(data)
    }

    /// `Base64::decode`: strict (mbedtls) decoding; `None` when the input is
    /// not valid base64. Spaces at line ends and `\n` / `\r\n` line breaks
    /// are accepted.
    ///
    /// As in C++ (`strlen(data.c_str())`), the input stops at the first NUL
    /// byte.
    pub fn decode(data: &[u8]) -> Option<Vec<u8>> {
        let len = data.iter().position(|&c| c == 0).unwrap_or(data.len());
        mbedtls_decode(&data[..len])
    }

    /// `Base64::decode_forgiven`: lenient decoding (`t:base64DecodeExt`).
    /// Never fails (always `Some`): invalid input decodes to an empty value.
    pub fn decode_forgiven(data: &[u8]) -> Option<Vec<u8>> {
        // base64HelperForgiven: a sizing call, then the decoding call.
        let out_len = Self::decode_forgiven_engine(&mut [], data);
        let mut ret = vec![0u8; out_len];
        if out_len > 0 {
            let out_len = Self::decode_forgiven_engine(&mut ret, data);
            ret.truncate(out_len);
        }
        Some(ret)
    }

    /// `Base64::decode_forgiven_engine`.
    ///
    /// With an empty `plain_text` this is the sizing call and the return
    /// value is the buffer size the decoding needs (0 on invalid input).
    /// Otherwise `plain_text` must be (at least) that size; the return value
    /// is then the number of decoded bytes.
    pub fn decode_forgiven_engine(plain_text: &mut [u8], encoded: &[u8]) -> usize {
        const B64_PAD: i32 = b'=' as i32;
        let plain_text_size = plain_text.len();
        let mut i: usize = 0;
        let mut j: usize = 0;
        let mut ch: i32 = 0;

        let mut pos = 0;
        while pos < encoded.len() {
            ch = i32::from(encoded[pos]);
            pos += 1;
            if ch == B64_PAD {
                // C++ reads `*encoded`, which is the string's NUL terminator
                // after the last byte.
                let next = encoded.get(pos).copied().unwrap_or(0);
                if next != b'=' && (i % 4) == 1 {
                    return 0;
                }
                continue;
            }
            ch = B64_REVERSE_T[ch as usize];
            if ch < 0 {
                continue;
            }
            match i % 4 {
                0 => {
                    if plain_text_size != 0 {
                        plain_text[j] = (ch << 2) as u8;
                    }
                }
                1 => {
                    if plain_text_size == 0 {
                        j += 1;
                    } else {
                        plain_text[j] |= (ch >> 4) as u8;
                        j += 1;
                        plain_text[j] = ((ch & 0x0f) << 4) as u8;
                    }
                }
                2 => {
                    if plain_text_size == 0 {
                        j += 1;
                    } else {
                        plain_text[j] |= (ch >> 2) as u8;
                        j += 1;
                        plain_text[j] = ((ch & 0x03) << 6) as u8;
                    }
                }
                _ => {
                    if plain_text_size == 0 {
                        j += 1;
                    } else {
                        plain_text[j] |= ch as u8;
                        j += 1;
                    }
                }
            }
            i += 1;
        }

        let mut k = j;
        // Quirk kept from C++: after a digit `ch` holds its *decoded* value,
        // so a final '9' (value 61 == '=') is also taken as padding.
        if ch == B64_PAD {
            match i % 4 {
                1 => return 0,
                2 => {
                    k += 1;
                    if plain_text_size != 0 {
                        plain_text[k] = 0;
                    }
                }
                3 if plain_text_size != 0 => {
                    plain_text[k] = 0;
                }
                _ => {}
            }
        }

        if plain_text_size != 0 {
            plain_text[j] = 0;
            j
        } else {
            k + 1
        }
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
        assert_eq!(Base64::decode_forgiven(b"Zm9vYmFy").unwrap(), b"foobar");
        assert_eq!(Base64::decode_forgiven(b"Zm9vYg").unwrap(), b"foob");
        assert_eq!(Base64::decode_forgiven(b"Zm9v.YmFy").unwrap(), b"foobar");
        assert_eq!(Base64::decode_forgiven(b"-_8=").unwrap(), b"\xfb\xff");
        // a lone digit followed by padding is invalid -> empty
        assert_eq!(Base64::decode_forgiven(b"Zm9vY=").unwrap(), b"");
        assert_eq!(Base64::decode_forgiven(b"").unwrap(), b"");
        assert_eq!(Base64::decode_with(b"Zm9v", true).unwrap(), b"foo");
        assert!(Base64::decode_with(b"Zm9", false).is_none());
    }
}
