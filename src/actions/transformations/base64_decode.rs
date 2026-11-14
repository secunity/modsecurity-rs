//! The `t:base64Decode` transformation: decodes base64 strictly, leaving
//! the value unchanged when it is not valid base64.

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
