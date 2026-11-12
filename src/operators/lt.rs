//! Port of `src/operators/lt.cc`, `src/operators/lt.h`.

use crate::operators::eq::atoll;
use crate::operators::operator::{Operator, Param};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct Lt {
    param: Param,
}

impl Lt {
    pub fn new(param: RunTimeString) -> Self {
        Lt { param: Param::expanded_in_message(param) }
    }
}

impl Operator for Lt {
    fn name(&self) -> &'static str {
        "Lt"
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
        let p = self.param.value(t);
        atoll(input) < atoll(&p)
    }
}
