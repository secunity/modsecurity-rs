//! Port of `src/operators/str_match.cc`, `src/operators/str_match.h`.

use crate::operators::operator::{Operator, OperatorBase};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;
use crate::utils::string::find;

#[derive(Debug)]
pub struct StrMatch {
    pub base: OperatorBase,
}

impl StrMatch {
    pub fn new(param: RunTimeString) -> Self {
        let mut base = OperatorBase::with_string("StrMatch", param);
        base.could_contain_macro = true;
        StrMatch { base }
    }
}

impl Operator for StrMatch {
    crate::operator_base_accessors!();
    fn evaluate(
        &self,
        t: Option<&mut Transaction<'_>>,
        _rule: Option<&RuleWithActions>,
        input: &[u8],
        _rm: Option<&mut RuleMessage<'_>>,
    ) -> bool {
        let p = self.base.string.as_ref().map_or_else(Vec::new, |s| s.evaluate(t.as_deref()));
        find(input, &p).is_some()
    }
}
