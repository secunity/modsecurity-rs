//! Port of `src/operators/validate_url_encoding.cc`,
//! `src/operators/validate_url_encoding.h`.

use crate::operators::operator::{Operator, OperatorBase, log_offset};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct ValidateUrlEncoding {
    pub base: OperatorBase,
}

impl Default for ValidateUrlEncoding {
    fn default() -> Self {
        Self::new()
    }
}

impl ValidateUrlEncoding {
    pub fn new() -> Self {
        ValidateUrlEncoding { base: OperatorBase::new("ValidateUrlEncoding") }
    }

    /// `validate_url_encoding`: 1 when valid, -1 for an empty input, -2 for
    /// non hexadecimal digits and -3 for a truncated `%xx`; `offset`
    /// receives the position of the offending `%`.
    pub fn validate_url_encoding(input: &[u8], offset: &mut usize) -> i32 {
        *offset = 0;

        if input.is_empty() {
            return -1;
        }

        let mut i = 0;
        while i < input.len() {
            if input[i] == b'%' {
                if i + 2 >= input.len() {
                    *offset = i;
                    // Not enough bytes.
                    return -3;
                } else {
                    // Here we only decode a %xx combination if it is valid,
                    // leaving it as is otherwise.
                    let c1 = input[i + 1];
                    let c2 = input[i + 2];

                    if c1.is_ascii_hexdigit() && c2.is_ascii_hexdigit() {
                        i += 3;
                    } else {
                        // Non-hexadecimal characters used in encoding.
                        *offset = i;
                        return -2;
                    }
                }
            } else {
                i += 1;
            }
        }

        1
    }
}

impl Operator for ValidateUrlEncoding {
    crate::operator_base_accessors!();
    fn evaluate(
        &self,
        t: &mut Transaction<'_>,
        _rule: &RuleWithActions,
        input: &[u8],
        rm: &mut RuleMessage<'_>,
    ) -> bool {
        let mut offset = 0;

        if input.is_empty() {
            return false;
        }

        let rc = Self::validate_url_encoding(input, &mut offset);
        let input_s = String::from_utf8_lossy(input);
        match rc {
            1 => {
                // Encoding is valid.
                crate::ms_dbg_a!(t, 7, "Valid URL Encoding at '{}'", input_s);

                false
            }
            -2 => {
                crate::ms_dbg_a!(t, 7, "Invalid URL Encoding: Non-hexadecimal digits used at '{}'", input_s);
                log_offset(rm, offset, input.len());

                true // Invalid match.
            }
            -3 => {
                crate::ms_dbg_a!(
                    t,
                    7,
                    "Invalid URL Encoding: Not enough characters at the end of input at '{}'",
                    input_s
                );
                log_offset(rm, offset, input.len());

                true // Invalid match.
            }
            _ => {
                crate::ms_dbg_a!(t, 7, "Invalid URL Encoding: Internal Error (rc = {}) at '{}'", rc, input_s);
                log_offset(rm, offset, input.len());

                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation() {
        let mut off = 0;
        assert_eq!(ValidateUrlEncoding::validate_url_encoding(b"a%20b", &mut off), 1);
        assert_eq!(ValidateUrlEncoding::validate_url_encoding(b"ab%2", &mut off), -3);
        assert_eq!(off, 2);
        assert_eq!(ValidateUrlEncoding::validate_url_encoding(b"x%zz", &mut off), -2);
        assert_eq!(off, 1);
        assert_eq!(ValidateUrlEncoding::validate_url_encoding(b"", &mut off), -1);
    }
}
