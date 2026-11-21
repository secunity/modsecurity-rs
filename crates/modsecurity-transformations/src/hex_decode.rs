//! The `t:hexDecode` transformation: decodes a hex-encoded value.

/// The value `t:hexDecode` gives a byte: its value as a hexadecimal digit,
/// and for any other byte what the same arithmetic gives (`0z` decodes to
/// `#`: `transformations/hexDecode.json` of the unit suite expects it).
fn digit_value(c: u8) -> u8 {
    if c >= b'A' { (c & 0xdf).wrapping_sub(b'A').wrapping_add(10) } else { c.wrapping_sub(b'0') }
}

/// Decodes pairs of hex digits in place (no validation: other bytes give
/// garbage bytes, and a trailing odd character is dropped).
fn inplace(value: &mut Vec<u8>) {
    let len = value.len() / 2;
    for d in 0..len {
        value[d] = digit_value(value[2 * d]).wrapping_mul(16).wrapping_add(digit_value(value[2 * d + 1]));
    }
    value.truncate(len);
}

/// Transforms `value` in place.
pub fn transform(value: &mut Vec<u8>) {
    inplace(value);
}
