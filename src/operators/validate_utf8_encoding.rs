//! Port of `src/operators/validate_utf8_encoding.cc`,
//! `src/operators/validate_utf8_encoding.h`.

use crate::operators::operator::{Operator, log_offset};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;

pub const UNICODE_ERROR_CHARACTERS_MISSING: i32 = -1;
pub const UNICODE_ERROR_INVALID_ENCODING: i32 = -2;
pub const UNICODE_ERROR_OVERLONG_CHARACTER: i32 = -3;
pub const UNICODE_ERROR_RESTRICTED_CHARACTER: i32 = -4;
pub const UNICODE_ERROR_DECODING_ERROR: i32 = -5;

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

    /// `detect_utf8_character`: the length of the UTF-8 character at the
    /// start of `p_read` or one of the `UNICODE_ERROR_*` codes.
    pub fn detect_utf8_character(p_read: &[u8]) -> i32 {
        let length = p_read.len();
        let unicode_len;
        let mut d: u32 = 0;

        let Some(&c) = p_read.first() else {
            return UNICODE_ERROR_DECODING_ERROR;
        };
        let c32 = u32::from(c);
        let at = |n: usize| u32::from(p_read[n]);

        if (c & 0x80) == 0 {
            // If the first byte begins with binary 0 it is a single byte
            // encoding: single byte unicode (7 bit ASCII equivalent) has no
            // validation.
            return 1;
        } else if (c & 0xE0) == 0xC0 {
            // If the first byte begins with binary 110 it is a two byte
            // encoding; check we have at least two bytes.
            if length < 2 {
                unicode_len = UNICODE_ERROR_CHARACTERS_MISSING;
            } else if (at(1) & 0xC0) != 0x80 {
                // check the second byte starts with binary 10
                unicode_len = UNICODE_ERROR_INVALID_ENCODING;
            } else {
                unicode_len = 2;
                // compute the character number
                d = ((c32 & 0x1F) << 6) | (at(1) & 0x3F);
            }
        } else if (c & 0xF0) == 0xE0 {
            // If the first byte begins with binary 1110 it is a three byte
            // encoding; check we have at least three bytes.
            if length < 3 {
                unicode_len = UNICODE_ERROR_CHARACTERS_MISSING;
            } else if (at(1) & 0xC0) != 0x80 || (at(2) & 0xC0) != 0x80 {
                // check the second and third bytes start with binary 10
                unicode_len = UNICODE_ERROR_INVALID_ENCODING;
            } else {
                unicode_len = 3;
                d = ((c32 & 0x0F) << 12) | ((at(1) & 0x3F) << 6) | (at(2) & 0x3F);
            }
        } else if (c & 0xF8) == 0xF0 {
            // If the first byte begins with binary 11110 it is a four byte
            // encoding; restrict characters to the UTF-8 range
            // (U+0000 - U+10FFFF).
            if c >= 0xF5 {
                return UNICODE_ERROR_RESTRICTED_CHARACTER;
            }
            if length < 4 {
                unicode_len = UNICODE_ERROR_CHARACTERS_MISSING;
            } else if (at(1) & 0xC0) != 0x80 || (at(2) & 0xC0) != 0x80 || (at(3) & 0xC0) != 0x80 {
                unicode_len = UNICODE_ERROR_INVALID_ENCODING;
            } else {
                unicode_len = 4;
                d = ((c32 & 0x07) << 18) | ((at(1) & 0x3F) << 12) | ((at(2) & 0x3F) << 6) | (at(3) & 0x3F);
            }
        } else {
            // any other first byte is invalid (RFC 3629)
            return UNICODE_ERROR_INVALID_ENCODING;
        }

        // invalid UTF-8 character number range (RFC 3629)
        if (0xD800..=0xDFFF).contains(&d) {
            return UNICODE_ERROR_RESTRICTED_CHARACTER;
        }

        // check for overlong
        if (unicode_len == 4 && d < 0x010000) || (unicode_len == 3 && d < 0x0800) || (unicode_len == 2 && d < 0x80) {
            // could be represented with less bytes
            return UNICODE_ERROR_OVERLONG_CHARACTER;
        }

        unicode_len
    }
}

impl Operator for ValidateUtf8Encoding {
    fn name(&self) -> &'static str {
        "ValidateUtf8Encoding"
    }
    fn evaluate(
        &self,
        t: &mut Transaction<'_>,
        _rule: &RuleWithActions,
        input: &[u8],
        rm: &mut RuleMessage<'_>,
    ) -> bool {
        let mut i = 0usize;
        while i < input.len() {
            let rc = Self::detect_utf8_character(&input[i..]);

            let msg = match rc {
                UNICODE_ERROR_CHARACTERS_MISSING => {
                    crate::ms_dbg_a!(
                        t,
                        8,
                        "Invalid UTF-8 encoding: not enough bytes in character at {}. [offset \"{}\"]",
                        String::from_utf8_lossy(input),
                        i
                    );

                    return true;
                }
                UNICODE_ERROR_INVALID_ENCODING => Some("Invalid UTF-8 encoding: invalid byte value in character at "),
                UNICODE_ERROR_OVERLONG_CHARACTER => Some("Invalid UTF-8 encoding: overlong character detected at "),
                UNICODE_ERROR_RESTRICTED_CHARACTER => Some("Invalid UTF-8 encoding: use of restricted character at "),
                UNICODE_ERROR_DECODING_ERROR => Some("Error validating UTF-8 decoding at "),
                _ if rc <= 0 => Some("Internal error during UTF-8 validation at "),
                _ => None,
            };

            if let Some(msg) = msg {
                crate::ms_dbg_a!(t, 8, "{}{}. [offset \"{}\"]", msg, String::from_utf8_lossy(input), i);
                log_offset(rm, i, input.len());

                return true;
            }

            i += rc as usize;
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect() {
        assert_eq!(ValidateUtf8Encoding::detect_utf8_character(b"a"), 1);
        assert_eq!(ValidateUtf8Encoding::detect_utf8_character("é".as_bytes()), 2);
        assert_eq!(ValidateUtf8Encoding::detect_utf8_character("€".as_bytes()), 3);
        assert_eq!(ValidateUtf8Encoding::detect_utf8_character("😀".as_bytes()), 4);
        assert_eq!(ValidateUtf8Encoding::detect_utf8_character(b"\xC3"), UNICODE_ERROR_CHARACTERS_MISSING);
        assert_eq!(ValidateUtf8Encoding::detect_utf8_character(b"\xC3\x41"), UNICODE_ERROR_INVALID_ENCODING);
        assert_eq!(ValidateUtf8Encoding::detect_utf8_character(b"\xC0\x80"), UNICODE_ERROR_OVERLONG_CHARACTER);
        assert_eq!(ValidateUtf8Encoding::detect_utf8_character(b"\xED\xA0\x80"), UNICODE_ERROR_RESTRICTED_CHARACTER);
        assert_eq!(
            ValidateUtf8Encoding::detect_utf8_character(b"\xF5\x80\x80\x80"),
            UNICODE_ERROR_RESTRICTED_CHARACTER
        );
        assert_eq!(ValidateUtf8Encoding::detect_utf8_character(b"\xFF"), UNICODE_ERROR_INVALID_ENCODING);
        assert_eq!(ValidateUtf8Encoding::detect_utf8_character(b""), UNICODE_ERROR_DECODING_ERROR);
    }
}
