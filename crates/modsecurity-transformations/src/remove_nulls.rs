//! The `t:removeNulls` transformation: removes NUL bytes.

/// Removes the bytes matching `pred`.
pub fn remove_if(val: &mut Vec<u8>, pred: impl Fn(u8) -> bool) {
    val.retain(|&c| !pred(c));
}

/// Transforms `value` in place.
pub fn transform(value: &mut Vec<u8>) {
    remove_if(value, |c| c == 0);
}
