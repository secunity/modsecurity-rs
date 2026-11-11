//! Port of `src/actions/transformations/escape_seq_decode.cc`, `src/actions/transformations/escape_seq_decode.h`.

use crate::actions::transformations::transformation::Transformation;
use crate::transaction::Transaction;
use crate::utils::string::{isodigit, x2c};

crate::transformation_struct!(EscapeSeqDecode);

/// `strtol(buf, NULL, base)` for a short buffer of valid digits.
fn strtol_digits(buf: &[u8], base: u32) -> i64 {
    buf.iter().fold(0i64, |acc, &c| acc * i64::from(base) + i64::from((c as char).to_digit(base).unwrap_or(0)))
}

fn ansi_c_sequences_decode_inplace(input: &mut Vec<u8>) -> bool {
    let input_len = input.len();
    // C++ may read the string's NUL terminator at `input_len`.
    let at = |input: &[u8], k: usize| input.get(k).copied().unwrap_or(0);
    let mut d = 0usize;
    let mut changed = false;
    let mut i = 0usize;

    while i < input_len {
        if input[i] == b'\\' && i + 1 < input_len {
            let mut c: i64 = match input[i + 1] {
                b'a' => 0x07,
                b'b' => 0x08,
                b'f' => 0x0c,
                b'n' => i64::from(b'\n'),
                b'r' => i64::from(b'\r'),
                b't' => i64::from(b'\t'),
                b'v' => 0x0b,
                b'\\' => i64::from(b'\\'),
                b'?' => i64::from(b'?'),
                b'\'' => i64::from(b'\''),
                b'"' => i64::from(b'"'),
                _ => -1,
            };

            if c != -1 {
                i += 2;
            }

            // Hexadecimal or octal?
            if c == -1 {
                if input[i + 1] == b'x' || input[i + 1] == b'X' {
                    // Hexadecimal.
                    if i + 3 < input_len && input[i + 2].is_ascii_hexdigit() && input[i + 3].is_ascii_hexdigit() {
                        // Two digits.
                        c = i64::from(x2c(&input[i + 2..i + 4]));
                        i += 4;
                    } else {
                        // Invalid encoding, do nothing.
                    }
                } else if isodigit(input[i + 1]) {
                    // Octal.
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
                        c = strtol_digits(&buf[..j], 8);
                        i += 1 + j;
                    }
                }
            }

            if c == -1 {
                // Didn't recognise encoding, copy raw bytes.
                input[d] = input[i + 1];
                d += 1;
                i += 2;
            } else {
                // Converted the encoding.
                input[d] = c as u8;
                d += 1;
            }

            changed = true;
        } else {
            // Input character not a backslash, copy it.
            input[d] = input[i];
            d += 1;
            i += 1;
        }
    }

    input.truncate(d);
    changed
}

impl Transformation for EscapeSeqDecode {
    fn transform(&self, value: &mut Vec<u8>, _t: Option<&Transaction<'_>>) -> bool {
        ansi_c_sequences_decode_inplace(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(input: &[u8]) -> (Vec<u8>, bool) {
        let mut v = input.to_vec();
        let changed = ansi_c_sequences_decode_inplace(&mut v);
        (v, changed)
    }

    #[test]
    fn decodes() {
        assert_eq!(run(b"\\n\\x41\\101"), (b"\nAA".to_vec(), true));
        // octal above one byte wraps (strtol result truncated to a byte)
        assert_eq!(run(b"\\777"), (vec![0xff], true));
        assert_eq!(run(b"\\xZ"), (b"xZ".to_vec(), true));
        assert_eq!(run(b"abc\\"), (b"abc\\".to_vec(), false));
    }
}
