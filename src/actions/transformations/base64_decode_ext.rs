//! The `t:base64DecodeExt` transformation: decodes base64 leniently
//! (invalid input decodes to an empty value).

use crate::utils::base64::Base64;

/// Transforms `value` in place; returns whether it changed.
pub fn transform(value: &mut Vec<u8>) -> bool {
    if value.is_empty() {
        return false;
    }
    match Base64::decode_forgiven(value) {
        Some(transformed) => {
            *value = transformed;
            true
        }
        None => false,
    }
}
