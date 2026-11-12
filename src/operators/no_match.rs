//! Port of `src/operators/no_match.cc`, `src/operators/no_match.h`.

use crate::operators::operator::Operator;
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;

/// Never matches.
#[derive(Debug)]
pub struct NoMatch;

impl Default for NoMatch {
    fn default() -> Self {
        Self::new()
    }
}

impl NoMatch {
    pub fn new() -> Self {
        NoMatch
    }
}

impl Operator for NoMatch {
    fn name(&self) -> &'static str {
        "NoMatch"
    }
    fn evaluate(
        &self,
        _t: &mut Transaction<'_>,
        _rule: &RuleWithActions,
        _input: &[u8],
        _rm: &mut RuleMessage<'_>,
    ) -> bool {
        false
    }
}
