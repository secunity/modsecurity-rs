//! The `t:removeWhitespace` transformation: removes whitespace and the
//! bytes 0xa0 and 0xc2 (non-breaking space).

use crate::actions::transformations::remove_nulls::remove_if;
use crate::utils::string::is_space;

/// Transforms `value` in place; returns whether it changed.
pub fn transform(value: &mut Vec<u8>) -> bool {
    const NON_BREAKING_SPACES: u8 = 0xa0;
    const NON_BREAKING_SPACES2: u8 = 0xc2;
    // remove whitespaces and non breaking spaces (NBSP)
    remove_if(value, |c| is_space(c) || c == NON_BREAKING_SPACES || c == NON_BREAKING_SPACES2)
}
