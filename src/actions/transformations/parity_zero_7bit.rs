//! Port of `src/actions/transformations/parity_zero_7bit.cc`, `src/actions/transformations/parity_zero_7bit.h`.

use crate::actions::transformations::transformation::Transformation;
use crate::transaction::Transaction;

crate::transformation_struct!(ParityZero7bit);

fn inplace(value: &mut [u8]) -> bool {
    if value.is_empty() {
        return false;
    }
    for c in value.iter_mut() {
        *c &= 0x7f;
    }
    true
}

impl Transformation for ParityZero7bit {
    fn transform(&self, value: &mut Vec<u8>, _t: Option<&Transaction<'_>>) -> bool {
        inplace(value)
    }
}
