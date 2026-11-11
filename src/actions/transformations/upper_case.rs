//! Port of `src/actions/transformations/upper_case.cc`, `src/actions/transformations/upper_case.h`.

use crate::actions::transformations::lower_case::LowerCase;
use crate::actions::transformations::transformation::Transformation;
use crate::transaction::Transaction;

crate::transformation_struct!(UpperCase);

impl Transformation for UpperCase {
    fn transform(&self, value: &mut Vec<u8>, _t: Option<&Transaction<'_>>) -> bool {
        // std::toupper in the C locale.
        LowerCase::convert(value, |c| c.to_ascii_uppercase())
    }
}
