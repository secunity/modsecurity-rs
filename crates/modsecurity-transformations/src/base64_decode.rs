//! The `t:base64Decode` transformation: decodes base64 strictly, leaving
//! the value unchanged when it is not valid base64.

use crate::base64::Base64;

/// Transforms `value` in place.
pub fn transform(value: &mut Vec<u8>) {
    if value.is_empty() {
        return;
    }
    if let Some(transformed) = Base64::decode(value) {
        *value = transformed;
    }
}
