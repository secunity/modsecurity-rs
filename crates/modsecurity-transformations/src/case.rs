//! The `t:lowercase` and `t:uppercase` transformations.

/// Applies `op` to every byte.
fn convert(val: &mut [u8], op: impl Fn(u8) -> u8) {
    for c in val.iter_mut() {
        *c = op(*c);
    }
}

/// `t:lowercase`: ASCII letters only, other bytes are left as they are.
pub fn lower(value: &mut [u8]) {
    convert(value, |c| c.to_ascii_lowercase());
}

/// `t:uppercase`: ASCII letters only, other bytes are left as they are.
pub fn upper(value: &mut [u8]) {
    convert(value, |c| c.to_ascii_uppercase());
}
