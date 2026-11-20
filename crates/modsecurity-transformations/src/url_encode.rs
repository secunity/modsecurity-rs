//! The `t:urlEncode` transformation: URL-encodes the value (a space
//! becomes `+`).

use crate::chars::c2x;

fn url_enc(value: &mut Vec<u8>) {
    let mut ret = Vec::with_capacity(value.len() * 3 + 1);

    // ENH Only encode the characters that really need to be encoded.
    for &c in value.iter() {
        if c == b' ' {
            ret.push(b'+');
        } else if c == b'*' || c.is_ascii_digit() || c.is_ascii_uppercase() || c.is_ascii_lowercase() {
            ret.push(c);
        } else {
            ret.push(b'%');
            c2x(u32::from(c), &mut ret);
        }
    }

    *value = ret;
}

/// Transforms `value` in place.
pub fn transform(value: &mut Vec<u8>) {
    url_enc(value);
}
