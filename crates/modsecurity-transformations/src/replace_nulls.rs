//! The `t:replaceNulls` transformation: replaces NUL bytes with spaces.

/// Transforms `value` in place.
pub fn transform(value: &mut [u8]) {
    for c in value.iter_mut() {
        if *c == 0 {
            *c = b' ';
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_nul_bytes_with_spaces() {
        let mut v = b"\0a\0b\0\0".to_vec();
        transform(&mut v);
        assert_eq!(v, b" a b  ");
        let mut v = b"ab".to_vec();
        transform(&mut v);
        assert_eq!(v, b"ab");
    }
}
