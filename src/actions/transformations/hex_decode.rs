//! Port of `src/actions/transformations/hex_decode.cc`, `src/actions/transformations/hex_decode.h`.

use crate::actions::transformations::transformation::Transformation;
use crate::transaction::Transaction;
use crate::utils::string::x2c;

crate::transformation_struct!(HexDecode);

/// Decodes pairs of hex digits in place (no validation: invalid digits give
/// garbage bytes, and a trailing odd character is dropped).
fn inplace(value: &mut Vec<u8>) -> bool {
    if value.is_empty() {
        return false;
    }
    let len = value.len();
    let mut d = 0usize;
    let mut i = 0usize;
    while i + 1 < len {
        value[d] = x2c(&value[i..i + 2]);
        d += 1;
        i += 2;
    }
    value.truncate(d);
    true
}

impl Transformation for HexDecode {
    fn transform(&self, value: &mut Vec<u8>, _t: Option<&Transaction<'_>>) -> bool {
        inplace(value)
    }
}
