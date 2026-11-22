//! The `t:base64Decode` transformation: decodes base64 strictly, leaving
//! the value unchanged when it is not valid base64.

use crate::base64::Base64;

/// Transforms `value` in place.
pub fn transform(value: &mut Vec<u8>) {
    if value.is_empty() {
        return;
    }
    if let Some(transformed) = Base64::decode(value) {
        *value = transformed;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(input: &[u8]) -> Vec<u8> {
        let mut v = input.to_vec();
        transform(&mut v);
        v
    }

    #[test]
    fn decodes_valid_base64() {
        assert_eq!(run(b"Zm9vYmFy"), b"foobar");
        assert_eq!(run(b"Zm9vYg=="), b"foob");
        assert_eq!(run(b"Zm9v\r\nYmFy"), b"foobar");
    }

    #[test]
    fn leaves_invalid_base64_unchanged() {
        assert_eq!(run(b"Zm9"), b"Zm9");
        assert_eq!(run(b"not base64!"), b"not base64!");
        assert_eq!(run(b"Zm9v_w=="), b"Zm9v_w==");
        assert_eq!(run(b""), b"");
    }

    #[test]
    fn stops_at_the_first_nul() {
        assert_eq!(run(b"Zm9v\0Zm9v"), b"foo");
    }
}
