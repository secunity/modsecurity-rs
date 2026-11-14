//! The `t:hexEncode` transformation: encodes every byte as two lowercase
//! hex digits.

use crate::utils::string::string_to_hex;

/// Transforms `value` in place; returns whether it changed.
pub fn transform(value: &mut Vec<u8>) -> bool {
    if value.is_empty() {
        return false;
    }
    *value = string_to_hex(value).into_bytes();
    true
}
