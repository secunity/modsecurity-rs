//! Port of `src/actions/transformations/parity_odd_7bit.cc`, `src/actions/transformations/parity_odd_7bit.h`.

use crate::actions::transformations::parity_even_7bit::ParityEven7bit;
use crate::actions::transformations::transformation::Transformation;
use crate::transaction::Transaction;

crate::transformation_struct!(ParityOdd7bit);

impl Transformation for ParityOdd7bit {
    fn transform(&self, value: &mut Vec<u8>, _t: Option<&Transaction<'_>>) -> bool {
        ParityEven7bit::inplace(value, false)
    }
}
