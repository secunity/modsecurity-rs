//! The `t:sqlHexDecode` transformation: decodes SQL hex literals
//! (`0xHHHH...`).

use crate::chars::hex_pair;

/// Decodes SQL hex literals (`0x` or `0X` followed by pairs of hex digits)
/// in place; an odd last digit is kept as it is.
fn inplace(value: &mut Vec<u8>) {
    let mut d = 0usize;
    let mut data = 0usize;

    while data < value.len() {
        if value[data] == b'0'
            && value.get(data + 1).is_some_and(|x| x.eq_ignore_ascii_case(&b'x'))
            && hex_pair(&value[data + 2..]).is_some()
        {
            data += 2;
            while let Some(byte) = hex_pair(&value[data..]) {
                value[d] = byte;
                d += 1;
                data += 2;
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
