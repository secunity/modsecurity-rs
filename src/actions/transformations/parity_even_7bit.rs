//! Port of `src/actions/transformations/parity_even_7bit.cc`, `src/actions/transformations/parity_even_7bit.h`.

use crate::actions::transformations::transformation::Transformation;
use crate::transaction::Transaction;

crate::transformation_struct!(ParityEven7bit);

impl ParityEven7bit {
    /// `ParityEven7bit::inplace<even>`: sets the high bit of every byte so
    /// that the byte has even (`even == true`) or odd parity.
    pub fn inplace(value: &mut [u8], even: bool) -> bool {
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
}

impl Transformation for ParityEven7bit {
    fn transform(&self, value: &mut Vec<u8>, _t: Option<&Transaction<'_>>) -> bool {
        ParityEven7bit::inplace(value, true)
    }
}
