//! Port of `src/operators/ge.cc`, `src/operators/ge.h`.

use crate::operators::eq::atoll;
use crate::operators::operator::{Operator, OperatorBase};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct Ge {
    pub base: OperatorBase,
}

impl Ge {
    pub fn new(param: RunTimeString) -> Self {
        let mut base = OperatorBase::with_string("Ge", param);
        base.could_contain_macro = true;
        Ge { base }
    }
}

impl Operator for Ge {
    crate::operator_base_accessors!();
    fn evaluate(
        &self,
        t: &mut Transaction<'_>,
        _rule: &RuleWithActions,
        input: &[u8],
        _rm: &mut RuleMessage<'_>,
    ) -> bool {
        let p = self.base.param_value(t);
        atoll(input) >= atoll(&p)
    }
}
