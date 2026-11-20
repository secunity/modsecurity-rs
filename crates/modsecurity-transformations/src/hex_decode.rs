//! The `t:hexDecode` transformation: decodes a hex-encoded value.

use crate::chars::x2c;

/// Decodes pairs of hex digits in place (no validation: invalid digits give
/// garbage bytes, and a trailing odd character is dropped).
fn inplace(value: &mut Vec<u8>) {
    let len = value.len();
    let mut d = 0usize;
    let mut i = 0usize;
    while i + 1 < len {
        value[d] = x2c(&value[i..i + 2]);
        d += 1;
        i += 2;
    }
    value.truncate(d);
}

/// Transforms `value` in place.
pub fn transform(value: &mut Vec<u8>) {
    inplace(value);
}
