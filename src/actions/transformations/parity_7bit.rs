//! Port of `src/actions/transformations/parity_even_7bit.cc`,
//! `parity_odd_7bit.cc` and `parity_zero_7bit.cc` (with their headers).

/// `ParityEven7bit::inplace<even>`: sets the high bit of every byte so that
/// the byte has even (`even == true`) or odd parity.
fn set_parity(value: &mut [u8], even: bool) -> bool {
    if value.is_empty() {
        return false;
    }
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
    true
}

/// `t:parityEven7bit`
pub fn even(value: &mut [u8]) -> bool {
    set_parity(value, true)
}

/// `t:parityOdd7bit`
pub fn odd(value: &mut [u8]) -> bool {
    set_parity(value, false)
}

/// `t:parityZero7bit`: clears the high bit of every byte.
pub fn zero(value: &mut [u8]) -> bool {
    if value.is_empty() {
        return false;
    }
    for c in value.iter_mut() {
        *c &= 0x7f;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parity() {
        let mut v = *b"\x01\x03\x81";
        assert!(even(&mut v));
        // The high bit counts in the parity: 0x81 has even parity already.
        assert_eq!(v, *b"\x81\x03\x01");
        assert!(odd(&mut v));
        assert_eq!(v, *b"\x81\x83\x01");
        assert!(zero(&mut v));
        assert_eq!(v, *b"\x01\x03\x01");
        assert!(!even(&mut []));
    }
}
