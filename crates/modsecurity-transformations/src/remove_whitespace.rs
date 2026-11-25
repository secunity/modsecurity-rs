//! The `t:removeWhitespace` transformation: removes whitespace and the
//! bytes of a non-breaking space, in ISO 8859-1 (0xa0) and in UTF-8 (0xc2
//! 0xa0).

use crate::chars::is_space;
use crate::remove_nulls::remove_if;

/// Transforms `value` in place.
pub fn transform(value: &mut Vec<u8>) {
    /// The non-breaking space of ISO 8859-1, and the second byte of
    /// U+00A0 in UTF-8.
    const NBSP: u8 = 0xa0;
    /// The first byte of U+00A0 in UTF-8. It is removed wherever it is,
    /// as C++ does, also when it starts another character.
    const UTF8_NBSP_LEAD: u8 = 0xc2;
    remove_if(value, |c| is_space(c) || c == NBSP || c == UTF8_NBSP_LEAD);
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
    fn removes_whitespace() {
        assert_eq!(run(b" a\tb\r\nc\x0b\x0c "), b"abc");
        assert_eq!(run(b""), b"");
    }

    #[test]
    fn removes_the_bytes_of_a_non_breaking_space() {
        assert_eq!(run(b"a\xc2\xa0b\xa0c"), b"abc");
        // Both bytes are removed wherever they appear, also inside other
        // UTF-8 characters (U+00A9 is C2 A9).
        assert_eq!(run(b"\xc2\xa9"), b"\xa9");
        assert_eq!(run(b"\xc3\xa9"), b"\xc3\xa9");
    }
}
