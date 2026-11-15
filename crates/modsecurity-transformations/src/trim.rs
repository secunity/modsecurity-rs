//! The `t:trim`, `t:trimLeft` and `t:trimRight` transformations: remove
//! whitespace from the ends of the value.

use crate::chars::is_space;

/// Removes leading whitespace; returns whether any was removed.
pub fn ltrim(s: &mut Vec<u8>) -> bool {
    let start = s.iter().position(|&c| !is_space(c)).unwrap_or(s.len());
    s.drain(..start);
    start != 0
}

/// Removes trailing whitespace; returns whether any was removed.
pub fn rtrim(s: &mut Vec<u8>) -> bool {
    let end = s.iter().rposition(|&c| !is_space(c)).map_or(0, |p| p + 1);
    let changed = end != s.len();
    s.truncate(end);
    changed
}

/// Removes leading and trailing whitespace; returns whether any was
/// removed.
pub fn trim(s: &mut Vec<u8>) -> bool {
    let mut changed = false;
    changed |= rtrim(s);
    changed |= ltrim(s);
    changed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trims() {
        let mut v = b" \t a b \r\n".to_vec();
        assert!(trim(&mut v));
        assert_eq!(v, b"a b");
        assert!(!trim(&mut v));
        let mut v = b"   ".to_vec();
        assert!(ltrim(&mut v));
        assert!(v.is_empty());
        let mut v = b"  x ".to_vec();
        assert!(rtrim(&mut v));
        assert_eq!(v, b"  x");
    }
}
