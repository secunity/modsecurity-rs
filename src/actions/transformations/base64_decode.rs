//! Port of `src/actions/transformations/base64_decode.cc`, `src/actions/transformations/base64_decode.h`.

use crate::actions::transformations::transformation::Transformation;
use crate::transaction::Transaction;
use crate::utils::base64::Base64;

crate::transformation_struct!(Base64Decode);

impl Transformation for Base64Decode {
    fn transform(&self, value: &mut Vec<u8>, _t: Option<&Transaction<'_>>) -> bool {
        if value.is_empty() {
            return false;
        }
        match Base64::decode(value) {
            Some(transformed) => {
                *value = transformed;
                true
            }
            None => false,
        }
    }
}
