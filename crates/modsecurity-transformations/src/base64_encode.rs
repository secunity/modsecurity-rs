//! The `t:base64Encode` transformation: encodes the value as base64.

use crate::base64::Base64;

/// Transforms `value` in place.
pub fn transform(value: &mut Vec<u8>) {
    if value.is_empty() {
        return;
    }
    *value = Base64::encode(value);
}
