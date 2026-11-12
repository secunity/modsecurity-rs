//! Port of `src/actions/transformations/base64_decode.cc`, `src/actions/transformations/base64_decode.h`.

use crate::utils::base64::Base64;

/// Transforms `value` in place; returns whether it changed.
pub fn transform(value: &mut Vec<u8>) -> bool {
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
