//! The `t:replaceNulls` transformation: replaces NUL bytes with spaces.

/// Transforms `value` in place.
pub fn transform(value: &mut [u8]) {
    for c in value.iter_mut() {
        if *c == 0 {
            *c = b' ';
        }
    }
}
