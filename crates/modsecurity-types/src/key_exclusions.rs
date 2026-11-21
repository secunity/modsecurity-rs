//! The keys excluded from a variable (`!ARGS:foo`, `!ARGS:/regex/`).

use modsecurity_native::regex::{CompileError, Regex};

/// Whether `a` and `b` name the same target or key: `ARGS:password`,
/// `args:Password` and `ARGS:PASSWORD` are one (keys are looked up
/// ignoring case). Every way of removing a target by its name compares
/// with this: `!ARGS:name` in a rule or in `SecRuleUpdateTarget...`, and
/// `ctl:ruleRemoveTargetBy...`.
pub fn same_name(a: &[u8], b: &[u8]) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// A key excluded from a variable (`!ARGS:foo` or `!ARGS:/regex/`).
#[derive(Debug)]
pub enum KeyExclusion {
    /// The keys a regular expression matches (case insensitive).
    Regex(Regex),
    /// One key, compared with [`same_name`].
    String(Vec<u8>),
}

impl KeyExclusion {
    /// The keys `re` matches, ignoring case; fails when `re` does not
    /// compile.
    pub fn regex(re: &str) -> Result<Self, CompileError> {
        Ok(KeyExclusion::Regex(Regex::compile(re.as_bytes(), true, true)?))
    }

    pub fn string(a: &str) -> Self {
        KeyExclusion::String(a.as_bytes().to_vec())
    }

    pub fn matches(&self, a: &[u8]) -> bool {
        match self {
            KeyExclusion::Regex(r) => r.is_match(a),
            KeyExclusion::String(k) => same_name(a, k),
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
        ke.push(KeyExclusion::regex("^pass").unwrap());
        assert!(ke.to_omit(b"id"));
        assert!(ke.to_omit(b"ID"));
        assert!(!ke.to_omit(b"idx"));
        assert!(ke.to_omit(b"PASSWORD"));
        assert!(!ke.to_omit(b"xpass"));
        assert_eq!(KeyExclusion::regex("(").unwrap_err().pattern, "(");
    }
}
