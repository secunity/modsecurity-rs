//! Port of `src/operators/within.cc`, `src/operators/within.h`.

use crate::operators::operator::{Operator, OperatorBase, log_offset};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;
use crate::utils::string::find;

#[derive(Debug)]
pub struct Within {
    pub base: OperatorBase,
}

impl Within {
    pub fn new(param: RunTimeString) -> Self {
        let mut base = OperatorBase::with_string("Within", param);
        base.could_contain_macro = true;
        Within { base }
    }
}

impl Operator for Within {
    crate::operator_base_accessors!();
    fn evaluate(
        &self,
        t: Option<&mut Transaction<'_>>,
        _rule: Option<&RuleWithActions>,
        input: &[u8],
        rm: Option<&mut RuleMessage<'_>>,
    ) -> bool {
        let param_target = self.base.string.as_ref().map_or_else(Vec::new, |s| s.evaluate(t.as_deref()));

        if input.is_empty() {
            return true;
        }

        let pos = find(&param_target, input);
        if let (Some(pos), Some(rm)) = (pos, rm) {
            log_offset(rm, pos, input.len());
        }

        pos.is_some()
    }
}
