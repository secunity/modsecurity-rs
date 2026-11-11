//! Port of `src/actions/transformations/css_decode.cc`, `src/actions/transformations/css_decode.h`.

use crate::actions::transformations::transformation::Transformation;
use crate::transaction::Transaction;
use crate::utils::string::{is_space, valid_hex, x2c, xsingle2c};

crate::transformation_struct!(CssDecode);

/// Decode a string that contains CSS-escaped characters.
///
/// References:
///     http://www.w3.org/TR/REC-CSS2/syndata.html#q4
///     http://www.unicode.org/roadmaps/
fn css_decode_inplace(input: &mut Vec<u8>) -> bool {
    let input_len = input.len();
    let mut d = 0usize;
    let mut changed = false;
    let mut i = 0usize;

    while i < input_len {
        // Is the character a backslash?
        if input[i] == b'\\' {
            // Is there at least one more byte?
            if i + 1 < input_len {
                i += 1; // We are not going to need the backslash.

                // Check for 1-6 hex characters following the backslash
                let mut j = 0usize;
                while j < 6 && i + j < input_len && valid_hex(input[i + j]) {
                    j += 1;
                }

                if j > 0 {
                    // We have at least one valid hexadecimal character.
                    let mut fullcheck = false;

                    // For now just use the last two bytes.
                    match j {
                        // Number of hex characters
                        1 => {
                            input[d] = xsingle2c(input[i]);
                            d += 1;
                        }
                        2 | 3 => {
                            // Use the last two from the end.
                            input[d] = x2c(&input[i + j - 2..i + j]);
                            d += 1;
                        }
                        4 => {
                            // Use the last two from the end, but request
                            // a full width check.
                            input[d] = x2c(&input[i + j - 2..i + j]);
                            fullcheck = true;
                        }
                        5 => {
                            // Use the last two from the end, but request
                            // a full width check if the number is greater
                            // or equal to 0xFFFF.
                            input[d] = x2c(&input[i + j - 2..i + j]);
                            // Do full check if first byte is 0
                            if input[i] == b'0' {
                                fullcheck = true;
                            } else {
                                d += 1;
                            }
                        }
                        _ => {
                            // 6: Use the last two from the end, but request
                            // a full width check if the number is greater
                            // or equal to 0xFFFF.
                            input[d] = x2c(&input[i + j - 2..i + j]);
                            // Do full check if first/second bytes are 0
                            if input[i] == b'0' && input[i + 1] == b'0' {
                                fullcheck = true;
                            } else {
                                d += 1;
                            }
                        }
                    }

                    // Full width ASCII (0xff01 - 0xff5e) needs 0x20 added
                    if fullcheck {
                        if input[d] > 0x00
                            && input[d] < 0x5f
                            && (input[i + j - 3] == b'f' || input[i + j - 3] == b'F')
                            && (input[i + j - 4] == b'f' || input[i + j - 4] == b'F')
                        {
                            input[d] += 0x20;
                        }
                        d += 1;
                    }

                    // We must ignore a single whitespace after a hex escape
                    if i + j < input_len && is_space(input[i + j]) {
                        j += 1;
                    }

                    // Move over.
                    i += j;

                    changed = true;
                } else if input[i] == b'\n' {
                    // No hexadecimal digits after backslash
                    // A newline character following backslash is ignored.
                    i += 1;
                    changed = true;
                } else {
                    // The character after backslash is not a hexadecimal
                    // digit, nor a newline.
                    // Use one character after backslash as is.
                    input[d] = input[i];
                    d += 1;
                    i += 1;
                }
            } else {
                // No characters after backslash.
                // Do not include backslash in output
                // (continuation to nothing)
                i += 1;
                changed = true;
            }
        } else {
            // Character is not a backslash.
            // Copy one normal character to output.
            input[d] = input[i];
            d += 1;
            i += 1;
        }
    }

    input.truncate(d);
    changed
}

impl Transformation for CssDecode {
    fn transform(&self, value: &mut Vec<u8>, _t: Option<&Transaction<'_>>) -> bool {
        css_decode_inplace(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(input: &[u8]) -> (Vec<u8>, bool) {
        let mut v = input.to_vec();
        let changed = css_decode_inplace(&mut v);
        (v, changed)
    }

    #[test]
    fn decodes() {
        assert_eq!(run(b"\\41 b"), (b"Ab".to_vec(), true));
        assert_eq!(run(b"\\ff21"), (b"A".to_vec(), true)); // full width 'A'... + 0x20
        assert_eq!(run(b"\\0041"), (b"A".to_vec(), true));
        assert_eq!(run(b"a\\"), (b"a".to_vec(), true));
        assert_eq!(run(b"\\\nx"), (b"x".to_vec(), true));
        assert_eq!(run(b"\\zx"), (b"zx".to_vec(), false));
        assert_eq!(run(b"\\a"), (b"\x0a".to_vec(), true));
    }
}
