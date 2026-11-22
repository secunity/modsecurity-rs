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

    #[test]
    fn all_c_whitespace_is_trimmed() {
        let mut v = b"\x0b\x0c a \x0b\x0c".to_vec();
        trim(&mut v);
        assert_eq!(v, b"a");
    }

    #[test]
    fn other_bytes_are_kept() {
        // A non-breaking space is not whitespace here.
        let mut v = b"\xa0a\xa0".to_vec();
        trim(&mut v);
        assert_eq!(v, b"\xa0a\xa0");
        let mut v = b"\0a\0".to_vec();
        trim(&mut v);
        assert_eq!(v, b"\0a\0");
    }

    #[test]
    fn empty_and_all_whitespace() {
        for f in [trim, ltrim, rtrim] {
            let mut v: Vec<u8> = Vec::new();
            f(&mut v);
            assert!(v.is_empty());
            let mut v = b" \t\r\n ".to_vec();
            f(&mut v);
            assert!(v.is_empty());
        }
    }
}
