//! The `t:jsDecode` transformation: decodes JavaScript escape sequences.

use crate::chars::{hex_pair, isodigit};
use crate::in_place;

/// The byte `\uHHHH` decodes to: the low byte of the code point, plus
/// 0x20 for the full width forms of ASCII (U+FF01 to U+FF5E).
pub(crate) fn low_byte_of_code_point(high: u8, low: u8) -> u8 {
    if high == 0xff && (0x01..0x5f).contains(&low) { low + 0x20 } else { low }
}

/// The escape `s` starts with: the byte it decodes to and its length.
fn escape(s: &[u8]) -> Option<(u8, usize)> {
    // A backslash at the end is kept.
    let [b'\\', escape, rest @ ..] = s else {
        return None;
    };
    // The byte of the two hex digits at `at` in `rest`.
    let hex = |at: usize| rest.get(at..).and_then(hex_pair);
    if *escape == b'u'
        && let Some(high) = hex(0)
        && let Some(low) = hex(2)
    {
        return Some((low_byte_of_code_point(high, low), 6));
    }
    if *escape == b'x'
        && let Some(byte) = hex(0)
    {
        return Some((byte, 4));
    }
    if isodigit(*escape) {
        // \OOO: up to three digits, three only when their value fits a
        // byte (up to `\377`).
        let max = if *escape <= b'3' { 3 } else { 2 };
        let len = 1 + rest.iter().take(max - 1).take_while(|&&c| isodigit(c)).count();
        let value = s[1..=len].iter().fold(0u32, |acc, &c| acc * 8 + u32::from(c - b'0'));
        return Some((value as u8, 1 + len));
    }
    // \C. `\u` and `\x` without their hex digits are here too.
    let byte = match escape {
        b'a' => 0x07,
        b'b' => 0x08,
        b'f' => 0x0c,
        b'n' => b'\n',
        b'r' => b'\r',
        b't' => b'\t',
        b'v' => 0x0b,
        // Any other character (`\?`, `\\`, `\'`, `\"`, `\u`, ...) is kept,
        // without its backslash.
        &other => other,
    };
    Some((byte, 2))
}

/// Transforms `value` in place.
pub fn transform(value: &mut Vec<u8>) {
    in_place::decode(value, escape);
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
    fn decodes() {
        assert_eq!(run(b"\\u0041\\uff21\\x42"), b"AAB");
        assert_eq!(run(b"\\101\\477"), b"A'7");
        assert_eq!(run(b"\\q\\"), b"q\\");
        assert_eq!(run(b"plain"), b"plain");
    }

    #[test]
    fn simple_escapes() {
        assert_eq!(run(b"\\a\\b\\f\\n\\r\\t\\v"), b"\x07\x08\x0c\n\r\t\x0b");
        assert_eq!(run(b"\\\\\\'\\\""), b"\\'\"");
    }

    #[test]
    fn incomplete_hex_escapes_keep_the_letter() {
        assert_eq!(run(b"\\xZZ"), b"xZZ");
        assert_eq!(run(b"\\u12"), b"u12");
        assert_eq!(run(b"\\u12zz"), b"u12zz");
    }

    #[test]
    fn octal_escapes_stay_within_a_byte() {
        assert_eq!(run(b"\\0"), b"\0");
        assert_eq!(run(b"\\12"), b"\n");
        assert_eq!(run(b"\\377"), b"\xff");
        // `\400` would not fit: two digits are used.
        assert_eq!(run(b"\\400"), b" 0");
    }

    #[test]
    fn full_width_ascii() {
        assert_eq!(run(b"\\uff41"), b"a");
        // Not a full width form: the low byte.
        assert_eq!(run(b"\\u0391"), b"\x91");
        assert_eq!(run(b""), b"");
    }
}
