//! Port of `src/actions/transformations/js_decode.cc`, `src/actions/transformations/js_decode.h`.

use crate::utils::string::{isodigit, valid_hex, x2c};

fn inplace(input: &mut Vec<u8>) -> bool {
    let input_len = input.len();
    // C++ may read the string's NUL terminator at `input_len`.
    let at = |input: &[u8], k: usize| input.get(k).copied().unwrap_or(0);
    let mut d = 0usize;
    let mut changed = false;
    let mut i = 0usize;

    while i < input_len {
        if input[i] == b'\\' {
            // Character is an escape.

            if i + 5 < input_len
                && input[i + 1] == b'u'
                && valid_hex(input[i + 2])
                && valid_hex(input[i + 3])
                && valid_hex(input[i + 4])
                && valid_hex(input[i + 5])
            {
                // \uHHHH

                // Use only the lower byte.
                let mut c = x2c(&input[i + 4..i + 6]);

                // Full width ASCII (ff01 - ff5e) needs 0x20 added
                if c > 0x00
                    && c < 0x5f
                    && (input[i + 2] == b'f' || input[i + 2] == b'F')
                    && (input[i + 3] == b'f' || input[i + 3] == b'F')
                {
                    c += 0x20;
                }
                input[d] = c;
                d += 1;
                i += 6;
                changed = true;
            } else if i + 3 < input_len && input[i + 1] == b'x' && valid_hex(input[i + 2]) && valid_hex(input[i + 3]) {
                // \xHH
                input[d] = x2c(&input[i + 2..i + 4]);
                d += 1;
                i += 4;
                changed = true;
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
                    changed = true;
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
                changed = true;
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
    changed
}

/// Transforms `value` in place; returns whether it changed.
pub fn transform(value: &mut Vec<u8>) -> bool {
    inplace(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(input: &[u8]) -> (Vec<u8>, bool) {
        let mut v = input.to_vec();
        let changed = inplace(&mut v);
        (v, changed)
    }

    #[test]
    fn decodes() {
        assert_eq!(run(b"\\u0041\\uff21\\x42"), (b"AAB".to_vec(), true));
        assert_eq!(run(b"\\101\\477"), (b"A'7".to_vec(), true));
        assert_eq!(run(b"\\q\\"), (b"q\\".to_vec(), true));
        assert_eq!(run(b"plain"), (b"plain".to_vec(), false));
    }
}
