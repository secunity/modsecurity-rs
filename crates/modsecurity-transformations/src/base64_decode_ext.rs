//! The `t:base64DecodeExt` transformation: decodes base64 leniently
//! (invalid input decodes to an empty value).

use crate::base64::Base64;

/// Transforms `value` in place.
pub fn transform(value: &mut Vec<u8>) {
    if value.is_empty() {
        return;
    }
    *value = Base64::decode_forgiven(value);
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
    fn decodes_leniently() {
        assert_eq!(run(b"Zm9vYmFy"), b"foobar");
        // Missing padding and bytes that are not digits are fine.
        assert_eq!(run(b"Zm9vYg"), b"foob");
        assert_eq!(run(b"Zm9v.Ym Fy"), b"foobar");
        // The URL-safe alphabet.
        assert_eq!(run(b"-_8="), b"\xfb\xff");
    }

    #[test]
    fn invalid_input_gives_an_empty_value() {
        assert_eq!(run(b"Zm9vY="), b"");
        assert_eq!(run(b""), b"");
    }
}
