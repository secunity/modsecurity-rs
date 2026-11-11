//! Port of `src/operators/validate_hash.cc`, `src/operators/validate_hash.h`.

use crate::operators::operator::{Operator, OperatorBase};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;

/// Not implemented by libmodsecurity either: always matches.
/// Reference: https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual#validateHash
#[derive(Debug)]
pub struct ValidateHash {
    pub base: OperatorBase,
}

impl ValidateHash {
    pub fn new(param: RunTimeString) -> Self {
        ValidateHash { base: OperatorBase::with_string("ValidateHash", param) }
    }
}

impl Operator for ValidateHash {
    crate::operator_base_accessors!();
    fn evaluate(
        &self,
        _t: Option<&mut Transaction<'_>>,
        _rule: Option<&RuleWithActions>,
        _input: &[u8],
        _rm: Option<&mut RuleMessage<'_>>,
    ) -> bool {
        true
    }
}
