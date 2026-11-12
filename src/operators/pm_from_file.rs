//! Port of `src/operators/pm_from_file.cc`, `src/operators/pm_from_file.h`.

use std::io::Read;

use crate::operators::operator::{Operator, OperatorBase};
use crate::operators::pm::Pm;
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;
use crate::utils::https_client::HttpsClient;
use crate::utils::string::{is_space, split};
use crate::utils::system::find_resource;

/// `@pmFromFile`: like `@pm`, with the patterns read (one per line) from
/// local files or `https://` resources.
#[derive(Debug)]
pub struct PmFromFile {
    pub pm: Pm,
}

impl PmFromFile {
    pub fn new(param: RunTimeString) -> Self {
        Self::with_name("PmFromFile", param)
    }

    /// `PmFromFile(n, param)`
    pub fn with_name(name: &'static str, param: RunTimeString) -> Self {
        PmFromFile { pm: Pm::with_name(name, param) }
    }

    /// `isComment`: empty lines and lines whose first non blank character
    /// is `#`.
    fn is_comment(s: &[u8]) -> bool {
        if s.is_empty() {
            return true;
        }
        match s.iter().position(|&c| c == b'#') {
            Some(pos) => s[..pos].iter().all(|&c| is_space(c)),
            None => false,
        }
    }

    /// Adds the non comment lines of `content` (`std::getline` split).
    fn add_lines(&mut self, content: &[u8]) {
        let mut lines: Vec<&[u8]> = content.split(|&c| c == b'\n').collect();
        if content.is_empty() || content.ends_with(b"\n") {
            lines.pop();
        }
        for line in lines {
            if !Self::is_comment(line) {
                self.pm.p.add_pattern(line);
            }
        }
    }
}

impl Operator for PmFromFile {
    fn base(&self) -> &OperatorBase {
        &self.pm.base
    }
    fn base_mut(&mut self) -> &mut OperatorBase {
        &mut self.pm.base
    }

    fn init(&mut self, config: &str) -> Result<(), String> {
        let tokens = split(&self.pm.base.param, b' ');

        for token in tokens {
            if token.is_empty() {
                continue;
            }
            let token = String::from_utf8_lossy(&token).into_owned();

            if token.starts_with("https://") {
                let mut client = HttpsClient::new();
                if !client.download(&token) {
                    return Err(client.error.clone());
                }
                let content = std::mem::take(&mut client.content);
                self.add_lines(&content);
            } else {
                let lookup = find_resource(&token, config);
                let Ok(mut file) = std::fs::File::open(lookup.path.unwrap_or_default()) else {
                    return Err(format!("Failed to open file: '{}'. {}", token, lookup.looked_at));
                };
                let mut content = Vec::new();
                // A read error ends the stream, like a failing std::getline.
                let _ = file.read_to_end(&mut content);
                self.add_lines(&content);
            }
        }

        self.pm.prepare();
        Ok(())
    }

    fn evaluate(
        &self,
        t: &mut Transaction<'_>,
        rule: &RuleWithActions,
        input: &[u8],
        rm: &mut RuleMessage<'_>,
    ) -> bool {
        self.pm.evaluate_pm(t, rule, input, rm)
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
        let mut op = PmFromFile::new(RunTimeString::from_text("/nonexistent/x.txt"));
        let e = op.init("/etc/modsec.conf").unwrap_err();
        assert!(e.starts_with("Failed to open file: '/nonexistent/x.txt'. Looking at: "), "{}", e);
    }
}
