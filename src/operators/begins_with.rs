//! Port of `src/operators/begins_with.cc`, `src/operators/begins_with.h`.

use crate::operators::operator::{Operator, OperatorBase, log_offset};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct BeginsWith {
    pub base: OperatorBase,
}

impl BeginsWith {
    pub fn new(param: RunTimeString) -> Self {
        BeginsWith { base: OperatorBase::with_string("BeginsWith", param) }
    }
}

impl Operator for BeginsWith {
    crate::operator_base_accessors!();
    fn evaluate(
        &self,
        t: Option<&mut Transaction<'_>>,
        _rule: Option<&RuleWithActions>,
        input: &[u8],
        rm: Option<&mut RuleMessage<'_>>,
    ) -> bool {
        let p = self.base.string.as_ref().map_or_else(Vec::new, |s| s.evaluate(t.as_deref()));

        if input.len() < p.len() {
            false
        } else if input.starts_with(&p) {
            if let Some(rm) = rm {
                log_offset(rm, 0, p.len());
            }
            true
        } else {
            false
        }
    }
}
