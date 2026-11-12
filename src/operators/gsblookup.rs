//! Port of `src/operators/gsblookup.cc`, `src/operators/gsblookup.h`.

use crate::operators::operator::{Operator, Param};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;

/// Not implemented by libmodsecurity either: always matches.
/// Reference: https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual#gsblookup
#[derive(Debug)]
pub struct GsbLookup {
    param: Param,
}

impl GsbLookup {
    pub fn new(param: RunTimeString) -> Self {
        GsbLookup { param: Param::new(param) }
    }
}

impl Operator for GsbLookup {
    fn name(&self) -> &'static str {
        "GsbLookup"
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
