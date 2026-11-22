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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lower_changes_ascii_letters_only() {
        let mut v = b"AbC-Z@[\xc4\xff".to_vec();
        lower(&mut v);
        assert_eq!(v, b"abc-z@[\xc4\xff");
    }

    #[test]
    fn upper_changes_ascii_letters_only() {
        let mut v = b"aBc-z`{\xe4\xff".to_vec();
        upper(&mut v);
        assert_eq!(v, b"ABC-Z`{\xe4\xff");
    }

    #[test]
    fn empty() {
        let mut v: Vec<u8> = Vec::new();
        lower(&mut v);
        upper(&mut v);
        assert!(v.is_empty());
    }
}
