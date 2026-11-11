//! Port of `src/actions/transformations/trim_right.cc`, `src/actions/transformations/trim_right.h`.

use crate::actions::transformations::transformation::Transformation;
use crate::actions::transformations::trim::Trim;
use crate::transaction::Transaction;

crate::transformation_struct!(TrimRight);

impl Transformation for TrimRight {
    fn transform(&self, value: &mut Vec<u8>, _t: Option<&Transaction<'_>>) -> bool {
        Trim::rtrim(value)
    }
}
