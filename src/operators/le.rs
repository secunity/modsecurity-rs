//! Port of `src/operators/le.cc`, `src/operators/le.h`.

use crate::operators::eq::atoll;
use crate::operators::operator::{Operator, OperatorBase};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct Le {
    pub base: OperatorBase,
}

impl Le {
    pub fn new(param: RunTimeString) -> Self {
        let mut base = OperatorBase::with_string("Le", param);
        base.could_contain_macro = true;
        Le { base }
    }
}

impl Operator for Le {
    crate::operator_base_accessors!();
    fn evaluate(
        &self,
        t: Option<&mut Transaction<'_>>,
        _rule: Option<&RuleWithActions>,
        input: &[u8],
        _rm: Option<&mut RuleMessage<'_>>,
    ) -> bool {
        let p = self.base.string.as_ref().map_or_else(Vec::new, |s| s.evaluate(t.as_deref()));
        atoll(input) <= atoll(&p)
    }
}
