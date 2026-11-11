//! Port of `src/operators/ip_match_from_file.cc`,
//! `src/operators/ip_match_from_file.h`.

use crate::operators::ip_match::IpMatch;
use crate::operators::operator::{Operator, OperatorBase};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;
use crate::utils::system::find_resource;

/// `@ipMatchFromFile`: like `@ipMatch`, with the entries read from a local
/// file or an `https://` resource.
#[derive(Debug)]
pub struct IpMatchFromFile {
    pub ip_match: IpMatch,
}

impl IpMatchFromFile {
    pub fn new(param: RunTimeString) -> Self {
        Self::with_name("IpMatchFromFile", param)
    }

    /// `IpMatchFromFile(n, param)`
    pub fn with_name(name: &str, param: RunTimeString) -> Self {
        IpMatchFromFile { ip_match: IpMatch::with_name(name, param) }
    }
}

impl Operator for IpMatchFromFile {
    fn base(&self) -> &OperatorBase {
        &self.ip_match.base
    }
    fn base_mut(&mut self) -> &mut OperatorBase {
        &mut self.ip_match.base
    }

    fn init(&mut self, file: &str) -> Result<(), String> {
        let mut e = String::new();
        let param = String::from_utf8_lossy(&self.ip_match.base.param).into_owned();

        let res = if param.starts_with("https://") {
            self.ip_match.tree.add_from_url(&param, &mut e)
        } else {
            let mut error = String::new();
            let resf = find_resource(&param, file, &mut error);
            if resf.is_empty() {
                return Err(error);
            }
            self.ip_match.tree.add_from_file(&resf, &mut e)
        };

        if res { Ok(()) } else { Err(e) }
    }

    fn evaluate(
        &self,
        t: Option<&mut Transaction<'_>>,
        rule: Option<&RuleWithActions>,
        input: &[u8],
        rm: Option<&mut RuleMessage<'_>>,
    ) -> bool {
        self.ip_match.evaluate(t, rule, input, rm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_file() {
        let config = format!("{}/test/test-cases/regression/x.json", env!("CARGO_MANIFEST_DIR"));
        let mut op = IpMatchFromFile::new(RunTimeString::from_text("../data/ipMatchFromFile.txt"));
        op.init(&config).unwrap();
        assert!(op.evaluate(None, None, b"200.249.12.31", None));
        assert!(op.evaluate(None, None, b"::1", None));
        assert!(!op.evaluate(None, None, b"200.249.12.32", None));

        let mut op = IpMatchFromFile::new(RunTimeString::from_text("file-not-found.txt"));
        assert_eq!(
            op.init("operator-ipMatchFromFile.json").unwrap_err(),
            "Looking at: 'file-not-found.txt', 'file-not-found.txt', \
             'operator-ipMatchFromFile.json/file-not-found.txt', 'operator-ipMatchFromFile.json/file-not-found.txt'."
        );
    }
}
