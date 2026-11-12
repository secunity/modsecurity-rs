//! Port of `src/operators/unconditional_match.cc`, `src/operators/unconditional_match.h`.

use crate::operators::operator::{Operator, OperatorBase};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;

/// Always matches.
#[derive(Debug)]
pub struct UnconditionalMatch {
    pub base: OperatorBase,
}

impl Default for UnconditionalMatch {
    fn default() -> Self {
        Self::new()
    }
}

impl UnconditionalMatch {
    pub fn new() -> Self {
        UnconditionalMatch { base: OperatorBase::new("UnconditionalMatch") }
    }
}

impl Operator for UnconditionalMatch {
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
