//! The parameter of `@contains`, `@containsWord` and `@strmatch`: a text
//! to find in the input.

use memchr::memmem::Finder;

use crate::Param;

/// A searcher for the text of a parameter, built once for a parameter
/// without macros (one with macros is searched for as expanded for each
/// transaction).
#[derive(Debug)]
pub(crate) struct Needle(Option<Finder<'static>>);

impl Needle {
    pub(crate) fn new(param: &Param) -> Self {
        Needle((!param.contains_macro()).then(|| Finder::new(&param.literal).into_owned()))
    }

    /// The position of the first `text` in `input` at or after `from`;
    /// `text` is the parameter as the context gives it (its literal when
    /// it has no macros).
    pub(crate) fn find_from(&self, text: &[u8], input: &[u8], from: usize) -> Option<usize> {
        match &self.0 {
            Some(finder) => finder.find(input.get(from..)?).map(|p| p + from),
            None => modsecurity_compat::chars::find_from(input, text, from),
        }
    }

    /// The position of the first `text` in `input`.
    pub(crate) fn find(&self, text: &[u8], input: &[u8]) -> Option<usize> {
        self.find_from(text, input, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_and_without_macros() {
        for param in [Param::from_text("ab"), Param::new(b"ab".to_vec(), true)] {
            let needle = Needle::new(&param);
            assert_eq!(needle.find(b"ab", b"xxabab"), Some(2));
            assert_eq!(needle.find_from(b"ab", b"xxabab", 3), Some(4));
            assert_eq!(needle.find_from(b"ab", b"xxabab", 7), None);
        }
        let empty = Needle::new(&Param::from_text(""));
        assert_eq!(empty.find_from(b"", b"abc", 3), Some(3));
    }
}
