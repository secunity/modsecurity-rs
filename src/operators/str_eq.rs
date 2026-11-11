//! Port of `src/operators/str_eq.cc`, `src/operators/str_eq.h`.

use crate::operators::operator::{Operator, OperatorBase};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct StrEq {
    pub base: OperatorBase,
}

impl StrEq {
    pub fn new(param: RunTimeString) -> Self {
        StrEq { base: OperatorBase::with_string("StrEq", param) }
    }
}

impl Operator for StrEq {
    crate::operator_base_accessors!();
    fn evaluate(
        &self,
        t: Option<&mut Transaction<'_>>,
        _rule: Option<&RuleWithActions>,
        input: &[u8],
        _rm: Option<&mut RuleMessage<'_>>,
    ) -> bool {
        let pt = self.base.string.as_ref().map_or_else(Vec::new, |s| s.evaluate(t.as_deref()));
        pt.as_slice() == input
    }
}
