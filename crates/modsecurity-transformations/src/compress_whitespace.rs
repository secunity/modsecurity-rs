//! The `t:compressWhitespace` transformation: replaces each run of
//! whitespace with a single space.

use crate::chars::is_space;

/// Transforms `value` in place.
pub fn transform(value: &mut Vec<u8>) {
    let old_len = value.len();
    let mut in_white_space = false;
    let mut d = 0usize;
    for s in 0..old_len {
        let c = value[s];
        if is_space(c) {
            if in_white_space {
                continue;
            }
            in_white_space = true;
            value[d] = b' ';
            d += 1;
        } else {
            in_white_space = false;
            value[d] = c;
            d += 1;
        }
    }
    value.truncate(d);
}
