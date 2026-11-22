//! The `t:parityEven7bit`, `t:parityOdd7bit` and `t:parityZero7bit`
//! transformations: set or clear the high bit of every byte.

/// Sets the high bit of every byte so that the byte has even
/// (`even == true`) or odd parity.
fn set_parity(value: &mut [u8], even: bool) {
    for uc in value.iter_mut() {
        let x = *uc;
        let mut p = x ^ (x >> 4);
        p &= 0xf;
        let condition = (0x6996u32 >> p) & 1 != 0;
        if if even { condition } else { !condition } {
            *uc = x | 0x80;
        } else {
            *uc = x & 0x7f;
        }
    }
}

/// `t:parityEven7bit`: sets the high bit so that every byte has even
/// parity.
pub fn even(value: &mut [u8]) {
    set_parity(value, true);
}

/// `t:parityOdd7bit`: sets the high bit so that every byte has odd
/// parity.
pub fn odd(value: &mut [u8]) {
    set_parity(value, false);
}

/// `t:parityZero7bit`: clears the high bit of every byte.
pub fn zero(value: &mut [u8]) {
    for c in value.iter_mut() {
        *c &= 0x7f;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parity() {
        let mut v = *b"\x01\x03\x81";
        even(&mut v);
        // The high bit counts in the parity: 0x81 has even parity already.
        assert_eq!(v, *b"\x81\x03\x01");
        odd(&mut v);
        assert_eq!(v, *b"\x81\x83\x01");
        zero(&mut v);
        assert_eq!(v, *b"\x01\x03\x01");
        even(&mut []);
    }

    #[test]
    fn letters() {
        // 'A' (0x41) and 'B' (0x42) have two bits set: even parity already.
        let mut v = *b"AB";
        even(&mut v);
        assert_eq!(v, *b"AB");
        odd(&mut v);
        assert_eq!(v, [0xc1, 0xc2]);
        // 'a' (0x61) has three bits set.
        let mut v = *b"a";
        even(&mut v);
        assert_eq!(v, [0xe1]);
        let mut v = *b"a";
        odd(&mut v);
        assert_eq!(v, *b"a");
    }

    /// For 7-bit input. (The high bit of the input counts in the parity,
    /// so for bytes above 0x7f the result is the opposite: see `parity`.)
    #[test]
    fn every_7bit_byte_gets_the_parity_asked_for() {
        for b in 0..=0x7fu8 {
            let mut e = [b];
            even(&mut e);
            assert_eq!(e[0].count_ones() % 2, 0, "{b:#x}");
            assert_eq!(e[0] & 0x7f, b & 0x7f);
            let mut o = [b];
            odd(&mut o);
            assert_eq!(o[0].count_ones() % 2, 1, "{b:#x}");
            assert_eq!(o[0] & 0x7f, b & 0x7f);
        }
    }
}
