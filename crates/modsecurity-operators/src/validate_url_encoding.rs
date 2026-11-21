//! The `@validateUrlEncoding` operator: matches when the input holds an
//! invalid `%xx` escape.

use crate::{Context, Operator};

#[derive(Debug)]
pub struct ValidateUrlEncoding;

impl Default for ValidateUrlEncoding {
    fn default() -> Self {
        Self::new()
    }
}

/// Why a value is not valid URL encoding; each with the position of the
/// `%` at fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlEncodingError {
    /// A `%` not followed by two hexadecimal digits.
    NotHex(usize),
    /// A `%` too close to the end for two digits.
    Truncated(usize),
}

impl ValidateUrlEncoding {
    pub fn new() -> Self {
        ValidateUrlEncoding
    }

    /// Checks the `%xx` escapes of `input`.
    pub fn validate_url_encoding(input: &[u8]) -> Result<(), UrlEncodingError> {
        let mut i = 0;
        while i < input.len() {
            if input[i] != b'%' {
                i += 1;
            } else if i + 2 >= input.len() {
                return Err(UrlEncodingError::Truncated(i));
            } else if input[i + 1].is_ascii_hexdigit() && input[i + 2].is_ascii_hexdigit() {
                i += 3;
            } else {
                return Err(UrlEncodingError::NotHex(i));
            }
        }
        Ok(())
    }
}

impl Operator for ValidateUrlEncoding {
    fn name(&self) -> &'static str {
        "ValidateUrlEncoding"
    }
    fn evaluate(&self, cx: &mut dyn Context, input: &[u8]) -> bool {
        if input.is_empty() {
            return false;
        }
        let input_s = String::from_utf8_lossy(input);
        match Self::validate_url_encoding(input) {
            Ok(()) => {
                crate::ms_dbg!(cx, 7, "Valid URL Encoding at '{}'", input_s);
                false
            }
            Err(UrlEncodingError::NotHex(offset)) => {
                crate::ms_dbg!(cx, 7, "Invalid URL Encoding: Non-hexadecimal digits used at '{}'", input_s);
                cx.offset(offset, input.len());
                true
            }
            Err(UrlEncodingError::Truncated(offset)) => {
                crate::ms_dbg!(
                    cx,
                    7,
                    "Invalid URL Encoding: Not enough characters at the end of input at '{}'",
                    input_s
                );
                cx.offset(offset, input.len());
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
        let check = ValidateUrlEncoding::validate_url_encoding;
        assert_eq!(check(b"a%20b"), Ok(()));
        assert_eq!(check(b""), Ok(()));
        assert_eq!(check(b"ab%2"), Err(UrlEncodingError::Truncated(2)));
        assert_eq!(check(b"x%zz"), Err(UrlEncodingError::NotHex(1)));
    }
}
