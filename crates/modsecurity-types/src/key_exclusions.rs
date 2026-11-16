//! The keys excluded from a variable (`!ARGS:foo`, `!ARGS:/regex/`).

use modsecurity_native::regex::Regex;

/// A key excluded from a variable (`!ARGS:foo` or `!ARGS:/regex/`).
#[derive(Debug)]
pub enum KeyExclusion {
    /// The keys a regular expression matches (case insensitive).
    Regex(Regex),
    /// One key, stored upper case and compared case insensitively.
    String(Vec<u8>),
}

impl KeyExclusion {
    pub fn regex(re: &str) -> Self {
        KeyExclusion::Regex(Regex::new_case(re, true))
    }

    pub fn string(a: &str) -> Self {
        KeyExclusion::String(a.as_bytes().to_ascii_uppercase())
    }

    pub fn matches(&self, a: &[u8]) -> bool {
        match self {
            KeyExclusion::Regex(r) => r.is_match(a),
            KeyExclusion::String(k) => a.len() == k.len() && a.iter().zip(k).all(|(x, y)| x.to_ascii_uppercase() == *y),
        }
    }
}

/// The keys excluded from a variable.
#[derive(Debug, Default)]
pub struct KeyExclusions(pub Vec<KeyExclusion>);

impl KeyExclusions {
    pub fn new() -> Self {
        KeyExclusions(Vec::new())
    }

    /// Whether the key `a` is excluded.
    pub fn to_omit(&self, a: &[u8]) -> bool {
        self.0.iter().any(|z| z.matches(a))
    }

    pub fn push(&mut self, k: KeyExclusion) {
        self.0.push(k);
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_and_regexes_are_case_insensitive() {
        let mut ke = KeyExclusions::new();
        assert!(ke.is_empty());
        assert!(!ke.to_omit(b"id"));
        ke.push(KeyExclusion::string("Id"));
        ke.push(KeyExclusion::regex("^pass"));
        assert!(ke.to_omit(b"id"));
        assert!(ke.to_omit(b"ID"));
        assert!(!ke.to_omit(b"idx"));
        assert!(ke.to_omit(b"PASSWORD"));
        assert!(!ke.to_omit(b"xpass"));
    }
}
