//! The `t:escapeSeqDecode` transformation: decodes ANSI C escape
//! sequences (`\n`, `\x41`, `\101`, ...).

use crate::chars::{hex_pair, isodigit};

/// The byte the escape sequence at the start of `seq` (just after its
/// backslash) decodes to, and the length of the sequence; `None` when it
/// is not one.
fn decode_escape(seq: &[u8]) -> Option<(u8, usize)> {
    let byte = match *seq.first()? {
        b'a' => 0x07,
        b'b' => 0x08,
        b'f' => 0x0c,
        b'n' => b'\n',
        b'r' => b'\r',
        b't' => b'\t',
        b'v' => 0x0b,
        c @ (b'\\' | b'?' | b'\'' | b'"') => c,
        // \xHH
        b'x' | b'X' => return hex_pair(&seq[1..]).map(|byte| (byte, 3)),
        // \O, \OO or \OOO; a value above 0xff keeps its low byte.
        c if isodigit(c) => {
            let digits = seq.iter().take(3).take_while(|&&c| isodigit(c)).count();
            let value = seq[..digits].iter().fold(0u32, |acc, &c| acc * 8 + u32::from(c - b'0'));
            return Some((value as u8, digits));
        }
        _ => return None,
    };
    Some((byte, 1))
}

fn ansi_c_sequences_decode_inplace(input: &mut Vec<u8>) {
    let mut d = 0usize;
    let mut i = 0usize;

    while i < input.len() {
        if input[i] == b'\\' && i + 1 < input.len() {
            match decode_escape(&input[i + 1..]) {
                Some((byte, len)) => {
                    input[d] = byte;
                    i += 1 + len;
                }
                None => {
                    // Not an escape sequence: the byte after the backslash.
                    input[d] = input[i + 1];
                    i += 2;
                }
            }
        } else {
            input[d] = input[i];
            i += 1;
        }
        d += 1;
    }

    input.truncate(d);
}

/// Transforms `value` in place.
pub fn transform(value: &mut Vec<u8>) {
    ansi_c_sequences_decode_inplace(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(input: &[u8]) -> Vec<u8> {
        let mut v = input.to_vec();
        ansi_c_sequences_decode_inplace(&mut v);
        v
    }

    #[test]
    fn decodes() {
        assert_eq!(run(b"\\n\\x41\\101"), b"\nAA");
        // octal above one byte wraps (strtol result truncated to a byte)
        assert_eq!(run(b"\\777"), vec![0xff]);
        assert_eq!(run(b"\\xZ"), b"xZ");
        assert_eq!(run(b"abc\\"), b"abc\\");
    }

    #[test]
    fn simple_escapes() {
        assert_eq!(run(b"\\a\\b\\f\\n\\r\\t\\v"), b"\x07\x08\x0c\n\r\t\x0b");
        assert_eq!(run(b"\\\\\\?\\'\\\""), b"\\?'\"");
    }

    #[test]
    fn hex_escapes() {
        assert_eq!(run(b"\\X41\\x6a"), b"Aj");
        // One digit is not enough.
        assert_eq!(run(b"\\x4"), b"x4");
    }

    #[test]
    fn octal_escapes_take_up_to_three_digits() {
        assert_eq!(run(b"\\0"), b"\0");
        assert_eq!(run(b"\\12x"), b"\nx");
        assert_eq!(run(b"\\1234"), b"S4");
    }

    #[test]
    fn unknown_escapes_keep_the_character() {
        assert_eq!(run(b"\\q\\8"), b"q8");
        assert_eq!(run(b""), b"");
    }
}
