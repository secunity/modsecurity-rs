//! Port of `src/operators/validate_hash.cc`, `src/operators/validate_hash.h`.

use crate::operators::operator::{Operator, Param};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;

/// Not implemented by libmodsecurity either: always matches.
/// Reference: https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual#validateHash
#[derive(Debug)]
pub struct ValidateHash {
    param: Param,
}

impl ValidateHash {
    pub fn new(param: RunTimeString) -> Self {
        ValidateHash { param: Param::new(param) }
    }
}

impl Operator for ValidateHash {
    fn name(&self) -> &'static str {
        "ValidateHash"
    }

    fn param(&self) -> Option<&Param> {
        Some(&self.param)
    }
    fn evaluate(
        &self,
        _t: &mut Transaction<'_>,
        _rule: &RuleWithActions,
        _input: &[u8],
        _rm: &mut RuleMessage<'_>,
    ) -> bool {
        true
    }
}
