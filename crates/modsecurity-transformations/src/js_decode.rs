//! The `t:jsDecode` transformation: decodes JavaScript escape sequences.

use crate::chars::{hex_pair, isodigit};

/// The byte `\uHHHH` decodes to: the low byte of the code point, plus
/// 0x20 for the full width forms of ASCII (U+FF01 to U+FF5E).
pub(crate) fn low_byte_of_code_point(high: u8, low: u8) -> u8 {
    if high == 0xff && (0x01..0x5f).contains(&low) { low + 0x20 } else { low }
}

fn inplace(input: &mut Vec<u8>) {
    let input_len = input.len();
    // A read at `input_len` (one past the last byte) sees 0.
    let at = |input: &[u8], k: usize| input.get(k).copied().unwrap_or(0);
    // The byte of the two hex digits at `k`.
    let hex_at = |input: &[u8], k: usize| input.get(k..).and_then(hex_pair);
    let mut d = 0usize;
    let mut i = 0usize;

    while i < input_len {
        if input[i] == b'\\' {
            // Character is an escape.
            let escape = input.get(i + 1).copied();

            if escape == Some(b'u')
                && let Some(high) = hex_at(input, i + 2)
                && let Some(low) = hex_at(input, i + 4)
            {
                // \uHHHH
                input[d] = low_byte_of_code_point(high, low);
                d += 1;
                i += 6;
            } else if escape == Some(b'x')
                && let Some(byte) = hex_at(input, i + 2)
            {
                // \xHH
                input[d] = byte;
                d += 1;
                i += 4;
            } else if i + 1 < input_len && isodigit(input[i + 1]) {
                // \OOO (only one byte, \000 - \377)
                let mut buf = [0u8; 3];
                let mut j = 0usize;

                while i + 1 + j < input_len && j < 3 {
                    buf[j] = input[i + 1 + j];
                    j += 1;
                    if !isodigit(at(input, i + 1 + j)) {
                        break;
                    }
                }

                if j > 0 {
                    // Do not use 3 characters if we will be > 1 byte
                    if j == 3 && buf[0] > b'3' {
                        j = 2;
                    }
                    // strtol(buf, NULL, 8) of at most "377": fits a byte.
                    let v = buf[..j].iter().fold(0u32, |acc, &c| acc * 8 + u32::from(c - b'0'));
                    input[d] = v as u8;
                    d += 1;
                    i += 1 + j;
                }
            } else if i + 1 < input_len {
                // \C
                let c = match input[i + 1] {
                    b'a' => 0x07,
                    b'b' => 0x08,
                    b'f' => 0x0c,
                    b'n' => b'\n',
                    b'r' => b'\r',
                    b't' => b'\t',
                    b'v' => 0x0b,
                    // The remaining (\?,\\,\',\") are just a removal
                    // of the escape char which is default.
                    other => other,
                };

                input[d] = c;
                d += 1;
                i += 2;
            } else {
                // Not enough bytes
                while i < input_len {
                    input[d] = input[i];
                    d += 1;
                    i += 1;
                }
            }
        } else {
            input[d] = input[i];
            d += 1;
            i += 1;
        }
    }

    input.truncate(d);
}

/// Transforms `value` in place.
pub fn transform(value: &mut Vec<u8>) {
    inplace(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(input: &[u8]) -> Vec<u8> {
        let mut v = input.to_vec();
        inplace(&mut v);
        v
    }

    #[test]
    fn decodes() {
        assert_eq!(run(b"\\u0041\\uff21\\x42"), b"AAB");
        assert_eq!(run(b"\\101\\477"), b"A'7");
        assert_eq!(run(b"\\q\\"), b"q\\");
        assert_eq!(run(b"plain"), b"plain");
    }
}
