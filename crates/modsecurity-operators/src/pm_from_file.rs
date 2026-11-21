//! The `@pmFromFile` (`@pmf`) operator.

use crate::pm::{Matcher, Pm};
use crate::{Context, Operator, Param, Resources};
use modsecurity_compat::chars::{is_space, split};

/// `@pmFromFile`: like `@pm`, with the patterns read (one per line) from
/// local files or `https://` resources.
#[derive(Debug)]
pub struct PmFromFile {
    pub pm: Pm,
}

impl PmFromFile {
    /// Reads the phrases of the files and URLs `param` names; `config` is
    /// the configuration file of the rule.
    pub fn new(param: Param, config: &str, resources: &dyn Resources) -> Result<Self, String> {
        Self::with_name("PmFromFile", param, config, resources)
    }

    /// An operator named `name` in messages (`PmFromF` for `@pmf`).
    pub fn with_name(
        name: &'static str,
        param: Param,
        config: &str,
        resources: &dyn Resources,
    ) -> Result<Self, String> {
        let mut contents: Vec<Vec<u8>> = Vec::new();

        for token in split(&param.literal, b' ') {
            if token.is_empty() {
                continue;
            }
            let token = String::from_utf8_lossy(&token).into_owned();

            if token.starts_with("https://") {
                contents.push(resources.download(&token)?);
            } else {
                let lookup = resources.find(&token, config);
                // A file that cannot be read completely is not used at all.
                let Ok(content) = std::fs::read(lookup.path.unwrap_or_default()) else {
                    return Err(format!("Failed to open file: '{}'. {}", token, lookup.looked_at));
                };
                contents.push(content);
            }
        }

        let p = Matcher::new(contents.iter().flat_map(|content| Self::phrases(content)));
        Ok(PmFromFile { pm: Pm::with_matcher(name, param, p) })
    }

    /// Whether a line is a comment: empty lines and lines whose first non
    /// blank character is `#`.
    fn is_comment(s: &[u8]) -> bool {
        if s.is_empty() {
            return true;
        }
        match s.iter().position(|&c| c == b'#') {
            Some(pos) => s[..pos].iter().all(|&c| is_space(c)),
            None => false,
        }
    }

    /// The non comment lines of `content` (split at `\n`; a final newline
    /// does not start another line).
    fn phrases(content: &[u8]) -> impl Iterator<Item = &[u8]> {
        let mut lines: Vec<&[u8]> = content.split(|&c| c == b'\n').collect();
        if content.is_empty() || content.ends_with(b"\n") {
            lines.pop();
        }
        lines.into_iter().filter(|line| !Self::is_comment(line))
    }
}

impl Operator for PmFromFile {
    fn name(&self) -> &'static str {
        self.pm.name()
    }

    fn param(&self) -> Option<&Param> {
        self.pm.param()
    }

    fn evaluate(&self, cx: &mut dyn Context, input: &[u8]) -> bool {
        self.pm.evaluate_pm(cx, input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comments() {
        assert!(PmFromFile::is_comment(b""));
        assert!(PmFromFile::is_comment(b"  # x"));
        assert!(!PmFromFile::is_comment(b"a # x"));
        assert!(!PmFromFile::is_comment(b"abc"));
    }

    #[test]
    fn missing_file() {
        let param = Param::from_text("/nonexistent/x.txt");
        let e = PmFromFile::new(param, "/etc/modsec.conf", &crate::test_support::LocalFiles).unwrap_err();
        assert!(e.starts_with("Failed to open file: '/nonexistent/x.txt'. Looking at: "), "{}", e);
    }
}
