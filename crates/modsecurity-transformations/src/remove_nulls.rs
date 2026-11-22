//! The `t:removeNulls` transformation: removes NUL bytes.

/// Removes the bytes matching `pred`.
pub fn remove_if(val: &mut Vec<u8>, pred: impl Fn(u8) -> bool) {
    val.retain(|&c| !pred(c));
}

/// Transforms `value` in place.
pub fn transform(value: &mut Vec<u8>) {
    remove_if(value, |c| c == 0);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(input: &[u8]) -> Vec<u8> {
        let mut v = input.to_vec();
        transform(&mut v);
        v
    }

    #[test]
    fn removes_nul_bytes() {
        assert_eq!(run(b"\0a\0\0b\0"), b"ab");
        assert_eq!(run(b"\0\0"), b"");
        assert_eq!(run(b"a b"), b"a b");
    }
}
