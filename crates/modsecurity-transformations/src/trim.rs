//! The `t:trim`, `t:trimLeft` and `t:trimRight` transformations: remove
//! whitespace from the ends of the value.

use crate::chars::is_space;

/// Removes leading whitespace.
pub fn ltrim(s: &mut Vec<u8>) {
    let start = s.iter().position(|&c| !is_space(c)).unwrap_or(s.len());
    s.drain(..start);
}

/// Removes trailing whitespace.
pub fn rtrim(s: &mut Vec<u8>) {
    let end = s.iter().rposition(|&c| !is_space(c)).map_or(0, |p| p + 1);
    s.truncate(end);
}

/// Removes leading and trailing whitespace.
pub fn trim(s: &mut Vec<u8>) {
    rtrim(s);
    ltrim(s);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trims() {
        let mut v = b" \t a b \r\n".to_vec();
        trim(&mut v);
        assert_eq!(v, b"a b");
        trim(&mut v);
        assert_eq!(v, b"a b");
        let mut v = b"   ".to_vec();
        ltrim(&mut v);
        assert!(v.is_empty());
        let mut v = b"  x ".to_vec();
        rtrim(&mut v);
        assert_eq!(v, b"  x");
    }
}
