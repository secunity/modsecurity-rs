//! Port of `src/actions/transformations/trim.cc`, `src/actions/transformations/trim.h`.

use crate::actions::transformations::transformation::Transformation;
use crate::transaction::Transaction;
use crate::utils::string::is_space;

crate::transformation_struct!(Trim);

impl Trim {
    /// `Trim::ltrim`: removes leading whitespace; returns whether any was
    /// removed.
    pub fn ltrim(s: &mut Vec<u8>) -> bool {
        let start = s.iter().position(|&c| !is_space(c)).unwrap_or(s.len());
        s.drain(..start);
        start != 0
    }

    /// `Trim::rtrim`: removes trailing whitespace; returns whether any was
    /// removed.
    pub fn rtrim(s: &mut Vec<u8>) -> bool {
        let end = s.iter().rposition(|&c| !is_space(c)).map_or(0, |p| p + 1);
        let changed = end != s.len();
        s.truncate(end);
        changed
    }

    /// `Trim::trim`
    pub fn trim(s: &mut Vec<u8>) -> bool {
        let mut changed = false;
        changed |= Self::rtrim(s);
        changed |= Self::ltrim(s);
        changed
    }
}

impl Transformation for Trim {
    fn transform(&self, value: &mut Vec<u8>, _t: Option<&Transaction<'_>>) -> bool {
        Trim::trim(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trims() {
        let mut v = b" \t a b \r\n".to_vec();
        assert!(Trim::trim(&mut v));
        assert_eq!(v, b"a b");
        assert!(!Trim::trim(&mut v));
        let mut v = b"   ".to_vec();
        assert!(Trim::ltrim(&mut v));
        assert!(v.is_empty());
        let mut v = b"  x ".to_vec();
        assert!(Trim::rtrim(&mut v));
        assert_eq!(v, b"  x");
    }
}
