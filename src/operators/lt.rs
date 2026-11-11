//! Port of `src/operators/lt.cc`, `src/operators/lt.h`.

use crate::operators::eq::atoll;
use crate::operators::operator::{Operator, OperatorBase};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct Lt {
    pub base: OperatorBase,
}

impl Lt {
    pub fn new(param: RunTimeString) -> Self {
        let mut base = OperatorBase::with_string("Lt", param);
        base.could_contain_macro = true;
        Lt { base }
    }
}

impl Operator for Lt {
    crate::operator_base_accessors!();
    fn evaluate(
        &self,
        t: Option<&mut Transaction<'_>>,
        _rule: Option<&RuleWithActions>,
        input: &[u8],
        _rm: Option<&mut RuleMessage<'_>>,
    ) -> bool {
        let p = self.base.string.as_ref().map_or_else(Vec::new, |s| s.evaluate(t.as_deref()));
        atoll(input) < atoll(&p)
    }
}
