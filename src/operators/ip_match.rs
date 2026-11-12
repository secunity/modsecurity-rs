//! Port of `src/operators/ip_match.cc`, `src/operators/ip_match.h`.

use crate::operators::operator::{Operator, Param};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;
use crate::utils::ip_tree::IpTree;

#[derive(Debug)]
pub struct IpMatch {
    name: &'static str,
    pub(crate) param: Param,
    pub(crate) tree: IpTree,
}

impl IpMatch {
    pub fn new(param: RunTimeString) -> Self {
        Self::with_name("IpMatch", param)
    }

    /// `IpMatch(n, param)`: used by `@ipMatchFromFile` / `@ipMatchF`.
    pub fn with_name(name: &'static str, param: RunTimeString) -> Self {
        IpMatch { name, param: Param::new(param), tree: IpTree::new() }
    }
}

impl Operator for IpMatch {
    fn name(&self) -> &'static str {
        self.name
    }

    fn param(&self) -> Option<&Param> {
        Some(&self.param)
    }

    fn init(&mut self, _file: &str) -> Result<(), String> {
        // An invalid list fails without a message, as in C++.
        if self.tree.add_from_buffer(&self.param.literal) { Ok(()) } else { Err(String::new()) }
    }

    fn evaluate(
        &self,
        _t: &mut Transaction<'_>,
        _rule: &RuleWithActions,
        input: &[u8],
        _rm: &mut RuleMessage<'_>,
    ) -> bool {
        self.tree.contains(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operators::operator::test_support::eval;

    #[test]
    fn ip_match() {
        let mut op = IpMatch::new(RunTimeString::from_text("127.0.0.1,192.168.0.0/24,::1"));
        op.init("").unwrap();
        assert!(eval(&op, b"127.0.0.1"));
        assert!(eval(&op, b"192.168.0.77"));
        assert!(!eval(&op, b"192.168.1.77"));
        assert!(eval(&op, b"::1"));
        assert!(!eval(&op, b"localhost"));
        let mut bad = IpMatch::new(RunTimeString::from_text("300.1.1.1"));
        assert!(bad.init("").is_err());
    }
}
