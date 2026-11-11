//! Port of `src/actions/transformations/lower_case.cc`, `src/actions/transformations/lower_case.h`.

use crate::actions::transformations::transformation::Transformation;
use crate::transaction::Transaction;

crate::transformation_struct!(LowerCase);

impl LowerCase {
    /// `LowerCase::convert`: applies `op` to every byte; returns whether any
    /// byte changed.
    pub fn convert(val: &mut [u8], op: impl Fn(u8) -> u8) -> bool {
        let mut changed = false;
        for c in val.iter_mut() {
            let nc = op(*c);
            if nc != *c {
                changed = true;
            }
            *c = nc;
        }
        changed
    }
}

impl Transformation for LowerCase {
    fn transform(&self, value: &mut Vec<u8>, _t: Option<&Transaction<'_>>) -> bool {
        // std::tolower in the C locale.
        LowerCase::convert(value, |c| c.to_ascii_lowercase())
    }
}
