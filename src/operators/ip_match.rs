//! Port of `src/operators/ip_match.cc`, `src/operators/ip_match.h`.

use crate::operators::operator::{Operator, OperatorBase};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;
use crate::utils::ip_tree::IpTree;

#[derive(Debug)]
pub struct IpMatch {
    pub base: OperatorBase,
    pub(crate) tree: IpTree,
}

impl IpMatch {
    pub fn new(param: RunTimeString) -> Self {
        Self::with_name("IpMatch", param)
    }

    /// `IpMatch(n, param)`: used by `@ipMatchFromFile` / `@ipMatchF`.
    pub fn with_name(name: &str, param: RunTimeString) -> Self {
        IpMatch { base: OperatorBase::with_string(name, param), tree: IpTree::new() }
    }
}

impl Operator for IpMatch {
    crate::operator_base_accessors!();

    fn init(&mut self, _file: &str) -> Result<(), String> {
        let mut e = String::new();
        if self.tree.add_from_buffer(&self.base.param, &mut e) { Ok(()) } else { Err(e) }
    }

    fn evaluate(
        &self,
        _t: Option<&mut Transaction<'_>>,
        _rule: Option<&RuleWithActions>,
        input: &[u8],
        _rm: Option<&mut RuleMessage<'_>>,
    ) -> bool {
        self.tree.contains(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_match() {
        let mut op = IpMatch::new(RunTimeString::from_text("127.0.0.1,192.168.0.0/24,::1"));
        op.init("").unwrap();
        assert!(op.evaluate(None, None, b"127.0.0.1", None));
        assert!(op.evaluate(None, None, b"192.168.0.77", None));
        assert!(!op.evaluate(None, None, b"192.168.1.77", None));
        assert!(op.evaluate(None, None, b"::1", None));
        assert!(!op.evaluate(None, None, b"localhost", None));
        let mut bad = IpMatch::new(RunTimeString::from_text("300.1.1.1"));
        assert!(bad.init("").is_err());
    }
}
