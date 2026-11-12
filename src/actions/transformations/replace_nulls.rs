//! Port of `src/actions/transformations/replace_nulls.cc`, `src/actions/transformations/replace_nulls.h`.

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
