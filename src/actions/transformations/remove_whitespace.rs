//! Port of `src/actions/transformations/remove_whitespace.cc`, `src/actions/transformations/remove_whitespace.h`.

use crate::actions::transformations::remove_nulls::RemoveNulls;
use crate::actions::transformations::transformation::Transformation;
use crate::transaction::Transaction;
use crate::utils::string::is_space;

crate::transformation_struct!(RemoveWhitespace);

impl Transformation for RemoveWhitespace {
    fn transform(&self, value: &mut Vec<u8>, _t: Option<&Transaction<'_>>) -> bool {
        const NON_BREAKING_SPACES: u8 = 0xa0;
        const NON_BREAKING_SPACES2: u8 = 0xc2;
        // remove whitespaces and non breaking spaces (NBSP)
        RemoveNulls::remove_if(value, |c| is_space(c) || c == NON_BREAKING_SPACES || c == NON_BREAKING_SPACES2)
    }
}
