//! Port of `src/actions/transformations/sql_hex_decode.cc`, `src/actions/transformations/sql_hex_decode.h`.

use crate::utils::string::{valid_hex, x2c};

#[inline]
fn mytolower(ch: u8) -> u8 {
    if ch.is_ascii_uppercase() { b'a' + ch - b'A' } else { ch }
}

/// Decodes SQL hex literals (`0xHHHH...`) in place.
fn inplace(value: &mut Vec<u8>) -> bool {
    if value.is_empty() {
        return false;
    }

    let end = value.len();
    let mut d = 0usize;
    let mut data = 0usize;
    let mut changed = false;

    while data < end {
        if data + 3 < end
            && value[data] == b'0'
            && mytolower(value[data + 1]) == b'x'
            && valid_hex(value[data + 2])
            && valid_hex(value[data + 3])
        {
            data += 2; // skip '0x'
            loop {
                value[d] = x2c(&value[data..data + 2]);
                d += 1;
                data += 2;
                if !(data + 1 < end && valid_hex(value[data]) && valid_hex(value[data + 1])) {
                    break;
                }
            }
            changed = true;
        } else {
            value[d] = value[data];
            d += 1;
            data += 1;
        }
    }

    value.truncate(d);
    changed
}

/// Transforms `value` in place; returns whether it changed.
pub fn transform(value: &mut Vec<u8>) -> bool {
    inplace(value)
}
