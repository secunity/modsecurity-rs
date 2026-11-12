//! Port of `src/actions/transformations/url_encode.cc`, `src/actions/transformations/url_encode.h`.

use crate::utils::string::c2x;

fn url_enc(value: &mut Vec<u8>) -> bool {
    let mut ret = Vec::with_capacity(value.len() * 3 + 1);
    let mut changed = false;

    // ENH Only encode the characters that really need to be encoded.
    for &c in value.iter() {
        if c == b' ' {
            ret.push(b'+');
            changed = true;
        } else if c == b'*' || c.is_ascii_digit() || c.is_ascii_uppercase() || c.is_ascii_lowercase() {
            ret.push(c);
        } else {
            ret.push(b'%');
            c2x(u32::from(c), &mut ret);
            changed = true;
        }
    }

    *value = ret;
    changed
}

/// Transforms `value` in place; returns whether it changed.
pub fn transform(value: &mut Vec<u8>) -> bool {
    url_enc(value)
}
