//! Port of `src/operators/unconditional_match.cc`, `src/operators/unconditional_match.h`.

use crate::operators::operator::Operator;
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;

/// Always matches.
#[derive(Debug)]
pub struct UnconditionalMatch;

impl Default for UnconditionalMatch {
    fn default() -> Self {
        Self::new()
    }
}

impl UnconditionalMatch {
    pub fn new() -> Self {
        UnconditionalMatch
    }
}

impl Operator for UnconditionalMatch {
    fn name(&self) -> &'static str {
        "UnconditionalMatch"
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
