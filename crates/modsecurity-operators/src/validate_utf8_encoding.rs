//! The `@validateUtf8Encoding` operator: matches when the input is not
//! valid UTF-8.

use crate::{Context, Operator};

/// Why the bytes at a position are not a UTF-8 character.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Utf8Error {
    /// The value ends before the character does.
    CharactersMissing,
    /// A byte that cannot be where it is.
    InvalidEncoding,
    /// A character written with more bytes than it needs.
    OverlongCharacter,
    /// A surrogate, or a code point above U+10FFFF.
    RestrictedCharacter,
}

#[derive(Debug)]
pub struct ValidateUtf8Encoding;

impl Default for ValidateUtf8Encoding {
    fn default() -> Self {
        Self::new()
    }
}

impl ValidateUtf8Encoding {
    pub fn new() -> Self {
        ValidateUtf8Encoding
    }

    /// The length of the UTF-8 character at the start of `p_read`.
    pub fn detect_utf8_character(p_read: &[u8]) -> Result<usize, Utf8Error> {
        use Utf8Error::*;
        let length = p_read.len();
        let unicode_len: usize;
        let d: u32;

        let Some(&c) = p_read.first() else {
            return Err(CharactersMissing);
        };
        let c32 = u32::from(c);
        let at = |n: usize| u32::from(p_read[n]);

        if (c & 0x80) == 0 {
            // If the first byte begins with binary 0 it is a single byte
            // encoding: single byte unicode (7 bit ASCII equivalent) has no
            // validation.
            return Ok(1);
        } else if (c & 0xE0) == 0xC0 {
            // If the first byte begins with binary 110 it is a two byte
            // encoding; check we have at least two bytes.
            if length < 2 {
                return Err(CharactersMissing);
            } else if (at(1) & 0xC0) != 0x80 {
                // check the second byte starts with binary 10
                return Err(InvalidEncoding);
            } else {
                unicode_len = 2;
                d = ((c32 & 0x1F) << 6) | (at(1) & 0x3F);
            }
        } else if (c & 0xF0) == 0xE0 {
            // If the first byte begins with binary 1110 it is a three byte
            // encoding; check we have at least three bytes.
            if length < 3 {
                return Err(CharactersMissing);
            } else if (at(1) & 0xC0) != 0x80 || (at(2) & 0xC0) != 0x80 {
                // check the second and third bytes start with binary 10
                return Err(InvalidEncoding);
            } else {
                unicode_len = 3;
                d = ((c32 & 0x0F) << 12) | ((at(1) & 0x3F) << 6) | (at(2) & 0x3F);
            }
        } else if (c & 0xF8) == 0xF0 {
            // If the first byte begins with binary 11110 it is a four byte
            // encoding; restrict characters to the UTF-8 range
            // (U+0000 - U+10FFFF).
            if c >= 0xF5 {
                return Err(RestrictedCharacter);
            }
            if length < 4 {
                return Err(CharactersMissing);
            } else if (at(1) & 0xC0) != 0x80 || (at(2) & 0xC0) != 0x80 || (at(3) & 0xC0) != 0x80 {
                return Err(InvalidEncoding);
            } else {
                unicode_len = 4;
                d = ((c32 & 0x07) << 18) | ((at(1) & 0x3F) << 12) | ((at(2) & 0x3F) << 6) | (at(3) & 0x3F);
            }
        } else {
            // any other first byte is invalid (RFC 3629)
            return Err(InvalidEncoding);
        }

        // Surrogates are not characters (RFC 3629).
        if (0xD800..=0xDFFF).contains(&d) {
            return Err(RestrictedCharacter);
        }

        // check for overlong
        if (unicode_len == 4 && d < 0x010000) || (unicode_len == 3 && d < 0x0800) || (unicode_len == 2 && d < 0x80) {
            // It could be written with fewer bytes.
            return Err(OverlongCharacter);
        }

        Ok(unicode_len)
    }
}

impl Operator for ValidateUtf8Encoding {
    fn name(&self) -> &'static str {
        "ValidateUtf8Encoding"
    }
    fn evaluate(&self, cx: &mut dyn Context, input: &[u8]) -> bool {
        let mut i = 0usize;
        while i < input.len() {
            let error = match Self::detect_utf8_character(&input[i..]) {
                Ok(len) => {
                    i += len;
                    continue;
                }
                Err(error) => error,
            };
            let msg = match error {
                Utf8Error::CharactersMissing => {
                    crate::ms_dbg!(
                        cx,
                        8,
                        "Invalid UTF-8 encoding: not enough bytes in character at {}. [offset \"{}\"]",
                        String::from_utf8_lossy(input),
                        i
                    );
                    return true;
                }
                Utf8Error::InvalidEncoding => "Invalid UTF-8 encoding: invalid byte value in character at ",
                Utf8Error::OverlongCharacter => "Invalid UTF-8 encoding: overlong character detected at ",
                Utf8Error::RestrictedCharacter => "Invalid UTF-8 encoding: use of restricted character at ",
            };
            crate::ms_dbg!(cx, 8, "{}{}. [offset \"{}\"]", msg, String::from_utf8_lossy(input), i);
            cx.offset(i, input.len());
            return true;
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect() {
        use Utf8Error::*;
        let detect = ValidateUtf8Encoding::detect_utf8_character;
        assert_eq!(detect(b"a"), Ok(1));
        assert_eq!(detect("é".as_bytes()), Ok(2));
        assert_eq!(detect("€".as_bytes()), Ok(3));
        assert_eq!(detect("😀".as_bytes()), Ok(4));
        assert_eq!(detect(b"\xC3"), Err(CharactersMissing));
        assert_eq!(detect(b"\xC3\x41"), Err(InvalidEncoding));
        assert_eq!(detect(b"\xC0\x80"), Err(OverlongCharacter));
        assert_eq!(detect(b"\xED\xA0\x80"), Err(RestrictedCharacter));
        assert_eq!(detect(b"\xF5\x80\x80\x80"), Err(RestrictedCharacter));
        assert_eq!(detect(b"\xFF"), Err(InvalidEncoding));
        assert_eq!(detect(b""), Err(CharactersMissing));
    }
}
