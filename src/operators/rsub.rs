//! Port of `src/operators/rsub.cc`, `src/operators/rsub.h`.

use crate::operators::operator::{Operator, OperatorBase};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;

/// Not implemented by libmodsecurity either: always matches.
/// Reference: https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual#rsub
#[derive(Debug)]
pub struct Rsub {
    pub base: OperatorBase,
}

impl Rsub {
    pub fn new(param: RunTimeString) -> Self {
        Rsub { base: OperatorBase::with_string("Rsub", param) }
    }
}

impl Operator for Rsub {
    crate::operator_base_accessors!();
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
