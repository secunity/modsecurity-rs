//! Port of `src/operators/str_eq.cc`, `src/operators/str_eq.h`.

use crate::operators::operator::{Operator, Param};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct StrEq {
    param: Param,
}

impl StrEq {
    pub fn new(param: RunTimeString) -> Self {
        StrEq { param: Param::new(param) }
    }
}

impl Operator for StrEq {
    fn name(&self) -> &'static str {
        "StrEq"
    }

    fn param(&self) -> Option<&Param> {
        Some(&self.param)
    }
    fn evaluate(
        &self,
        t: &mut Transaction<'_>,
        _rule: &RuleWithActions,
        input: &[u8],
        _rm: &mut RuleMessage<'_>,
    ) -> bool {
        let pt = self.param.value(t);
        *pt == *input
    }
}
