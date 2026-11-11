//! Port of `src/actions/transformations/base64_encode.cc`, `src/actions/transformations/base64_encode.h`.

use crate::actions::transformations::transformation::Transformation;
use crate::transaction::Transaction;
use crate::utils::base64::Base64;

crate::transformation_struct!(Base64Encode);

impl Transformation for Base64Encode {
    fn transform(&self, value: &mut Vec<u8>, _t: Option<&Transaction<'_>>) -> bool {
        if value.is_empty() {
            return false;
        }
        *value = Base64::encode(value);
        true
    }
}
