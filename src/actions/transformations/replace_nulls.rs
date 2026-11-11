//! Port of `src/actions/transformations/replace_nulls.cc`, `src/actions/transformations/replace_nulls.h`.

use crate::actions::transformations::transformation::Transformation;
use crate::transaction::Transaction;

crate::transformation_struct!(ReplaceNulls);

impl Transformation for ReplaceNulls {
    fn transform(&self, value: &mut Vec<u8>, _t: Option<&Transaction<'_>>) -> bool {
        let mut changed = false;
        for c in value.iter_mut() {
            if *c == 0 {
                *c = b' ';
                changed = true;
            }
        }
        changed
    }
}
