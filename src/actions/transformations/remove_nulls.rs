//! Port of `src/actions/transformations/remove_nulls.cc`, `src/actions/transformations/remove_nulls.h`.

use crate::actions::transformations::transformation::Transformation;
use crate::transaction::Transaction;

crate::transformation_struct!(RemoveNulls);

impl RemoveNulls {
    /// `RemoveNulls::remove_if`: removes the bytes matching `pred`; returns
    /// whether any was removed.
    pub fn remove_if(val: &mut Vec<u8>, pred: impl Fn(u8) -> bool) -> bool {
        let old_size = val.len();
        val.retain(|&c| !pred(c));
        val.len() != old_size
    }
}

impl Transformation for RemoveNulls {
    fn transform(&self, value: &mut Vec<u8>, _t: Option<&Transaction<'_>>) -> bool {
        RemoveNulls::remove_if(value, |c| c == 0)
    }
}
