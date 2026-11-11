//! Port of `src/actions/transformations/trim_left.cc`, `src/actions/transformations/trim_left.h`.

use crate::actions::transformations::transformation::Transformation;
use crate::actions::transformations::trim::Trim;
use crate::transaction::Transaction;

crate::transformation_struct!(TrimLeft);

impl Transformation for TrimLeft {
    fn transform(&self, value: &mut Vec<u8>, _t: Option<&Transaction<'_>>) -> bool {
        Trim::ltrim(value)
    }
}
