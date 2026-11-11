//! Port of `src/operators/gsblookup.cc`, `src/operators/gsblookup.h`.

use crate::operators::operator::{Operator, OperatorBase};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;

/// Not implemented by libmodsecurity either: always matches.
/// Reference: https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual#gsblookup
#[derive(Debug)]
pub struct GsbLookup {
    pub base: OperatorBase,
}

impl GsbLookup {
    pub fn new(param: RunTimeString) -> Self {
        GsbLookup { base: OperatorBase::with_string("GsbLookup", param) }
    }
}

impl Operator for GsbLookup {
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
