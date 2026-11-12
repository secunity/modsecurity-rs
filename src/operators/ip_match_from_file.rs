//! Port of `src/operators/ip_match_from_file.cc`,
//! `src/operators/ip_match_from_file.h`.

use crate::operators::ip_match::IpMatch;
use crate::operators::operator::{Operator, Param};
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
        IpMatchFromFile { ip_match: IpMatch::with_name("IpMatchFromFile", param) }
    }
}

impl Operator for IpMatchFromFile {
    fn name(&self) -> &'static str {
        self.ip_match.name()
    }

    fn param(&self) -> Option<&Param> {
        self.ip_match.param()
    }

    fn init(&mut self, file: &str) -> Result<(), String> {
        let param = self.ip_match.param.literal_lossy();

        if param.starts_with("https://") {
            self.ip_match.tree.add_from_url(&param)
        } else {
            let lookup = find_resource(&param, file);
            let Some(resf) = lookup.path else {
                return Err(lookup.looked_at);
            };
            self.ip_match.tree.add_from_file(&resf)
        }
    }

    fn evaluate(
        &self,
        t: &mut Transaction<'_>,
        rule: &RuleWithActions,
        input: &[u8],
        rm: &mut RuleMessage<'_>,
    ) -> bool {
        self.ip_match.evaluate(t, rule, input, rm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operators::operator::test_support::eval;

    #[test]
    fn from_file() {
        let config = format!("{}/test/test-cases/regression/x.json", env!("CARGO_MANIFEST_DIR"));
        let mut op = IpMatchFromFile::new(RunTimeString::from_text("../data/ipMatchFromFile.txt"));
        op.init(&config).unwrap();
        assert!(eval(&op, b"200.249.12.31"));
        assert!(eval(&op, b"::1"));
        assert!(!eval(&op, b"200.249.12.32"));

        let mut op = IpMatchFromFile::new(RunTimeString::from_text("file-not-found.txt"));
        assert_eq!(
            op.init("operator-ipMatchFromFile.json").unwrap_err(),
            "Looking at: 'file-not-found.txt', 'file-not-found.txt', \
             'operator-ipMatchFromFile.json/file-not-found.txt', 'operator-ipMatchFromFile.json/file-not-found.txt'."
        );
    }
}
