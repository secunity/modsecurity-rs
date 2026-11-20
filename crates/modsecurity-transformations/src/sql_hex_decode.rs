//! The `t:sqlHexDecode` transformation: decodes SQL hex literals
//! (`0xHHHH...`).

use crate::chars::x2c;

#[inline]
fn mytolower(ch: u8) -> u8 {
    if ch.is_ascii_uppercase() { b'a' + ch - b'A' } else { ch }
}

/// Decodes SQL hex literals (`0xHHHH...`) in place.
fn inplace(value: &mut Vec<u8>) {
    let end = value.len();
    let mut d = 0usize;
    let mut data = 0usize;

    while data < end {
        if data + 3 < end
            && value[data] == b'0'
            && mytolower(value[data + 1]) == b'x'
            && value[data + 2].is_ascii_hexdigit()
            && value[data + 3].is_ascii_hexdigit()
        {
            data += 2; // skip '0x'
            loop {
                value[d] = x2c(&value[data..data + 2]);
                d += 1;
                data += 2;
                if !(data + 1 < end && value[data].is_ascii_hexdigit() && value[data + 1].is_ascii_hexdigit()) {
                    break;
                }
            }
        } else {
            value[d] = value[data];
            d += 1;
            data += 1;
        }
    }

    value.truncate(d);
}

/// Transforms `value` in place.
pub fn transform(value: &mut Vec<u8>) {
    inplace(value);
}
