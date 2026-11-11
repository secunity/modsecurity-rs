//! Port of `src/actions/transformations/utf8_to_unicode.cc`, `src/actions/transformations/utf8_to_unicode.h`.

use crate::actions::transformations::transformation::Transformation;
use crate::transaction::Transaction;

crate::transformation_struct!(Utf8ToUnicode);

const UNICODE_ERROR_CHARACTERS_MISSING: i32 = -1;
const UNICODE_ERROR_INVALID_ENCODING: i32 = -2;

/// Appends `%u` followed by the code point in lowercase hex, zero padded to
/// (at least) four digits.
fn push_code_point(data: &mut Vec<u8>, d: u32) {
    data.extend_from_slice(format!("%u{d:04x}").as_bytes());
}

fn encode(value: &mut Vec<u8>) -> bool {
    let input = value.as_slice();
    let input_len = input.len();
    // C++ reads past the last byte into the string's NUL terminator
    // (the length checks below use the whole input length, not the bytes
    // left); such reads see 0, which fails every continuation-byte check.
    let at = |k: usize| input.get(k).copied().unwrap_or(0);
    let mut changed = false;
    let mut count: usize = 0;
    let bytes_left = input_len;

    // RFC3629 states that UTF-8 are encoded using sequences of 1 to 4 octets.
    // Max size per character should fit in 4 bytes
    let len = input_len * 4 + 1;
    let mut data: Vec<u8> = Vec::with_capacity(len);

    let mut i = 0usize;
    while i < bytes_left {
        let mut unicode_len: i32 = 0;
        let mut d: u32 = 0;
        let c = input[i];

        // If first byte begins with binary 0 it is single byte encoding
        if (c & 0x80) == 0 {
            // single byte unicode (7 bit ASCII equivilent) has no validation
            count += 1;
            if count <= len {
                if c == 0 && input_len > i + 1 {
                    // Quirk kept from C++: x2c(NUL, next) is written at the
                    // output position without advancing it, so it is
                    // overwritten by the next output byte (or cut off at
                    // the end): a NUL that is not the last byte is dropped.
                } else {
                    data.push(c);
                }
            }
        } else if (c & 0xE0) == 0xC0 {
            // If first byte begins with binary 110 it is two byte encoding
            // check we have at least two bytes
            if bytes_left < 2 {
                // check second byte starts with binary 10
                unicode_len = UNICODE_ERROR_CHARACTERS_MISSING;
            } else if (at(i + 1) & 0xC0) != 0x80 {
                unicode_len = UNICODE_ERROR_INVALID_ENCODING;
            } else {
                unicode_len = 2;
                count += 6;
                if count <= len {
                    // compute character number
                    d = ((u32::from(c) & 0x1F) << 6) | (u32::from(at(i + 1)) & 0x3F);
                    push_code_point(&mut data, d);
                    changed = true;
                }
            }
        } else if (c & 0xF0) == 0xE0 {
            // If first byte begins with binary 1110 it is three byte encoding
            // check we have at least three bytes
            if bytes_left < 3 {
                // check second byte starts with binary 10
                unicode_len = UNICODE_ERROR_CHARACTERS_MISSING;
            } else if (at(i + 1) & 0xC0) != 0x80 {
                // check third byte starts with binary 10
                unicode_len = UNICODE_ERROR_INVALID_ENCODING;
            } else if (at(i + 2) & 0xC0) != 0x80 {
                unicode_len = UNICODE_ERROR_INVALID_ENCODING;
            } else {
                unicode_len = 3;
                count += 6;
                if count <= len {
                    // compute character number
                    d = ((u32::from(c) & 0x0F) << 12)
                        | ((u32::from(at(i + 1)) & 0x3F) << 6)
                        | (u32::from(at(i + 2)) & 0x3F);
                    push_code_point(&mut data, d);
                    changed = true;
                }
            }
        } else if (c & 0xF8) == 0xF0 {
            // If first byte begins with binary 11110 it
            // is four byte encoding

            // restrict characters to UTF-8 range (U+0000 - U+10FFFF)
            if c >= 0xF5 {
                data.push(c);
            }
            // check we have at least four bytes
            if bytes_left < 4 {
                // check second byte starts with binary 10
                unicode_len = UNICODE_ERROR_CHARACTERS_MISSING;
            } else if (at(i + 1) & 0xC0) != 0x80 {
                // check third byte starts with binary 10
                unicode_len = UNICODE_ERROR_INVALID_ENCODING;
            } else if (at(i + 2) & 0xC0) != 0x80 {
                // check forth byte starts with binary 10
                unicode_len = UNICODE_ERROR_INVALID_ENCODING;
            } else if (at(i + 3) & 0xC0) != 0x80 {
                unicode_len = UNICODE_ERROR_INVALID_ENCODING;
            } else {
                unicode_len = 4;
                count += 7;
                if count <= len {
                    // compute character number
                    d = ((u32::from(c) & 0x07) << 18)
                        | ((u32::from(at(i + 1)) & 0x3F) << 12)
                        | ((u32::from(at(i + 2)) & 0x3F) << 6)
                        | (u32::from(at(i + 3)) & 0x3F);
                    push_code_point(&mut data, d);
                    changed = true;
                }
            }
        } else {
            // any other first byte is invalid (RFC 3629)
            count += 1;
            if count <= len {
                data.push(c);
            }
        }

        // invalid UTF-8 character number range (RFC 3629)
        if (0xD800..=0xDFFF).contains(&d) {
            count += 1;
            if count <= len {
                data.push(c);
            }
        }

        // check for overlong
        if (unicode_len == 4 && d < 0x010000) || (unicode_len == 3 && d < 0x0800) || (unicode_len == 2 && d < 0x80) {
            // could be represented with less bytes
            count += 1;
            if count <= len {
                data.push(c);
            }
        }

        if unicode_len > 0 {
            i += unicode_len as usize;
        } else {
            i += 1;
        }
    }

    *value = data;
    changed
}

impl Transformation for Utf8ToUnicode {
    fn transform(&self, value: &mut Vec<u8>, _t: Option<&Transaction<'_>>) -> bool {
        encode(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(input: &[u8]) -> (Vec<u8>, bool) {
        let mut v = input.to_vec();
        let changed = encode(&mut v);
        (v, changed)
    }

    #[test]
    fn encodes() {
        assert_eq!(run("aé€😀".as_bytes()), (b"a%u00e9%u20ac%u1f600".to_vec(), true));
        assert_eq!(run(b"plain"), (b"plain".to_vec(), false));
        // NUL inside the value is dropped, a final NUL is kept
        assert_eq!(run(b"a\0b\0"), (b"ab\0".to_vec(), false));
        // truncated / invalid sequences produce nothing for the lead byte
        assert_eq!(run(b"ab\xc3"), (b"ab".to_vec(), false));
        assert_eq!(run(b"\xc3("), (b"(".to_vec(), false));
        // overlong encodings also copy the lead byte
        assert_eq!(run(b"\xc0\xaf"), (b"%u002f\xc0".to_vec(), true));
        // invalid first byte copied as is
        assert_eq!(run(b"\xff"), (b"\xff".to_vec(), false));
    }
}
