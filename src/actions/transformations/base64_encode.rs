//! The `t:base64Encode` transformation: encodes the value as base64.

use crate::utils::base64::Base64;

/// Transforms `value` in place; returns whether it changed.
pub fn transform(value: &mut Vec<u8>) -> bool {
    if value.is_empty() {
        return false;
    }
    *value = Base64::encode(value);
    true
}
