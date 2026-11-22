//! The `t:removeWhitespace` transformation: removes whitespace and the
//! bytes 0xa0 and 0xc2 (non-breaking space).

use crate::chars::is_space;
use crate::remove_nulls::remove_if;

/// Transforms `value` in place.
pub fn transform(value: &mut Vec<u8>) {
    const NON_BREAKING_SPACES: u8 = 0xa0;
    const NON_BREAKING_SPACES2: u8 = 0xc2;
    // remove whitespaces and non breaking spaces (NBSP)
    remove_if(value, |c| is_space(c) || c == NON_BREAKING_SPACES || c == NON_BREAKING_SPACES2);
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
