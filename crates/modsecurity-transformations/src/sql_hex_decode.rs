//! The `t:sqlHexDecode` transformation: decodes SQL hex literals
//! (`0xHHHH...`).

use crate::chars::hex_pair;

/// Decodes SQL hex literals (`0x` or `0X` followed by pairs of hex digits)
/// in place; an odd last digit is kept as it is.
fn inplace(value: &mut Vec<u8>) {
    let mut d = 0usize;
    let mut data = 0usize;

    while data < value.len() {
        if value[data] == b'0'
            && value.get(data + 1).is_some_and(|x| x.eq_ignore_ascii_case(&b'x'))
            && hex_pair(&value[data + 2..]).is_some()
        {
            data += 2;
            while let Some(byte) = hex_pair(&value[data..]) {
                value[d] = byte;
                d += 1;
                data += 2;
            }
        } else {
            value[d] = value[data];
            d += 1;
            data += 1;
        }
    }

    value.truncate(d);
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
    fn decodes_hex_literals() {
        assert_eq!(run(b"0x414243"), b"ABC");
        assert_eq!(run(b"0X41"), b"A");
        assert_eq!(run(b"SELECT 0x41,0x42"), b"SELECT A,B");
        assert_eq!(run(b"10x41"), b"1A");
    }

    #[test]
    fn an_odd_last_digit_is_kept() {
        assert_eq!(run(b"0x414"), b"A4");
    }

    #[test]
    fn a_literal_needs_two_digits() {
        assert_eq!(run(b"0x"), b"0x");
        assert_eq!(run(b"0x4"), b"0x4");
        assert_eq!(run(b"0xZZ"), b"0xZZ");
        assert_eq!(run(b"x41"), b"x41");
        assert_eq!(run(b""), b"");
    }
}
