//! Port of `src/actions/transformations/length.cc`, `src/actions/transformations/length.h`.

use crate::actions::transformations::transformation::Transformation;
use crate::transaction::Transaction;

crate::transformation_struct!(Length);

impl Transformation for Length {
    fn transform(&self, value: &mut Vec<u8>, _t: Option<&Transaction<'_>>) -> bool {
        *value = value.len().to_string().into_bytes();
        true
    }
}
