//! The `t:hexDecode` transformation: decodes a hex-encoded value.

/// The value `t:hexDecode` gives a byte: its value as a hexadecimal digit,
/// and for any other byte what the same arithmetic gives (`0z` decodes to
/// `#`: `transformations/hexDecode.json` of the unit suite expects it).
fn digit_value(c: u8) -> u8 {
    if c >= b'A' { (c & 0xdf).wrapping_sub(b'A').wrapping_add(10) } else { c.wrapping_sub(b'0') }
}

/// Decodes pairs of hex digits in place (no validation: other bytes give
/// garbage bytes, and a trailing odd character is dropped).
fn inplace(value: &mut Vec<u8>) {
    let len = value.len() / 2;
    for d in 0..len {
        value[d] = digit_value(value[2 * d]).wrapping_mul(16).wrapping_add(digit_value(value[2 * d + 1]));
    }
    value.truncate(len);
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
        transform(&mut v);
        v
    }

    #[test]
    fn decodes_pairs_of_digits() {
        assert_eq!(run(b"414243"), b"ABC");
        assert_eq!(run(b"6a6B"), b"jk");
        assert_eq!(run(b"00ff"), b"\0\xff");
        assert_eq!(run(b""), b"");
    }

    #[test]
    fn a_trailing_odd_digit_is_dropped() {
        assert_eq!(run(b"41a"), b"A");
        assert_eq!(run(b"4"), b"");
    }

    #[test]
    fn other_bytes_decode_by_the_same_arithmetic() {
        // `transformations/hexDecode.json` of the unit suite expects it.
        assert_eq!(run(b"0z"), b"#");
    }
}
