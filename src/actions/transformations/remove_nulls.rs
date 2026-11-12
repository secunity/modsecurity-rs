//! Port of `src/actions/transformations/remove_nulls.cc`, `src/actions/transformations/remove_nulls.h`.

/// `RemoveNulls::remove_if`: removes the bytes matching `pred`; returns
/// whether any was removed.
pub fn remove_if(val: &mut Vec<u8>, pred: impl Fn(u8) -> bool) -> bool {
    let old_size = val.len();
    val.retain(|&c| !pred(c));
    val.len() != old_size
}

/// Transforms `value` in place; returns whether it changed.
pub fn transform(value: &mut Vec<u8>) -> bool {
    remove_if(value, |c| c == 0)
}
