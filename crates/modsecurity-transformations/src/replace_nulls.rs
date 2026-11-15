//! The `t:replaceNulls` transformation: replaces NUL bytes with spaces.

/// Transforms `value` in place; returns whether it changed.
pub fn transform(value: &mut [u8]) -> bool {
    let mut changed = false;
    for c in value.iter_mut() {
        if *c == 0 {
            *c = b' ';
            changed = true;
        }
    }
    changed
}
