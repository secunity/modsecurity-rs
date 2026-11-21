//! The `t:cssDecode` transformation: decodes CSS escape sequences.

use crate::chars::{hex_digit, is_space};

/// Decode a string that contains CSS-escaped characters.
///
/// References:
///     http://www.w3.org/TR/REC-CSS2/syndata.html#q4
///     http://www.unicode.org/roadmaps/
fn css_decode_inplace(input: &mut Vec<u8>) {
    let input_len = input.len();
    let mut d = 0usize;
    let mut i = 0usize;

    while i < input_len {
        if input[i] != b'\\' {
            // Copy one normal character to output.
            input[d] = input[i];
            d += 1;
            i += 1;
            continue;
        }
        // We are not going to need the backslash.
        i += 1;
        if i == input_len {
            // No characters after the backslash: continuation to nothing.
            break;
        }

        // Up to 6 hex digits following the backslash, and their value.
        let mut j = 0usize;
        let mut code_point = 0u32;
        while j < 6
            && let Some(digit) = input.get(i + j).copied().and_then(hex_digit)
        {
            code_point = code_point << 4 | u32::from(digit);
            j += 1;
        }

        if j > 0 {
            // Only the low byte is used. From 4 digits on, a code point up
            // to U+FFFF gets the full width check: the full width forms of
            // ASCII (U+FF01 to U+FF5E) need 0x20 added.
            let low = code_point as u8;
            let full_width_check = j == 4 || (j > 4 && code_point <= 0xffff);
            input[d] = if full_width_check && (code_point >> 8) & 0xff == 0xff && (0x01..0x5f).contains(&low) {
                low + 0x20
            } else {
                low
            };
            d += 1;

            // We must ignore a single whitespace after a hex escape.
            if i + j < input_len && is_space(input[i + j]) {
                j += 1;
            }
            i += j;
        } else if input[i] == b'\n' {
            // A newline character following the backslash is ignored.
            i += 1;
        } else {
            // The character after the backslash is not a hexadecimal
            // digit, nor a newline: it is used as is.
            input[d] = input[i];
            d += 1;
            i += 1;
        }
    }

    input.truncate(d);
}

/// Transforms `value` in place.
pub fn transform(value: &mut Vec<u8>) {
    css_decode_inplace(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(input: &[u8]) -> Vec<u8> {
        let mut v = input.to_vec();
        css_decode_inplace(&mut v);
        v
    }

    #[test]
    fn decodes() {
        assert_eq!(run(b"\\41 b"), b"Ab");
        assert_eq!(run(b"\\ff21"), b"A"); // full width 'A'... + 0x20
        assert_eq!(run(b"\\0041"), b"A");
        assert_eq!(run(b"a\\"), b"a");
        assert_eq!(run(b"\\\nx"), b"x");
        assert_eq!(run(b"\\zx"), b"zx");
        assert_eq!(run(b"\\a"), b"\x0a");
    }
}
