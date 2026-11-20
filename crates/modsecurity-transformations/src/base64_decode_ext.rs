//! The `t:base64DecodeExt` transformation: decodes base64 leniently
//! (invalid input decodes to an empty value).

use crate::base64::Base64;

/// Transforms `value` in place.
pub fn transform(value: &mut Vec<u8>) {
    if value.is_empty() {
        return;
    }
    if let Some(transformed) = Base64::decode_forgiven(value) {
        *value = transformed;
    }
}
