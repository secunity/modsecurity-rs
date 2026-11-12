//! Port of `src/operators/ge.cc`, `src/operators/ge.h`.

use crate::operators::eq::atoll;
use crate::operators::operator::{Operator, Param};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct Ge {
    param: Param,
}

impl Ge {
    pub fn new(param: RunTimeString) -> Self {
        Ge { param: Param::expanded_in_message(param) }
    }
}

impl Operator for Ge {
    fn name(&self) -> &'static str {
        "Ge"
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
        atoll(input) >= atoll(&p)
    }
}
