//! Port of `src/actions/transformations/hex_encode.cc`, `src/actions/transformations/hex_encode.h`.

use crate::actions::transformations::transformation::Transformation;
use crate::transaction::Transaction;
use crate::utils::string::string_to_hex;

crate::transformation_struct!(HexEncode);

impl Transformation for HexEncode {
    fn transform(&self, value: &mut Vec<u8>, _t: Option<&Transaction<'_>>) -> bool {
        if value.is_empty() {
            return false;
        }
        *value = string_to_hex(value).into_bytes();
        true
    }
}
