//! Port of `src/operators/begins_with.cc`, `src/operators/begins_with.h`.

use crate::operators::operator::{Operator, Param, log_offset};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct BeginsWith {
    param: Param,
}

impl BeginsWith {
    pub fn new(param: RunTimeString) -> Self {
        BeginsWith { param: Param::new(param) }
    }
}

impl Operator for BeginsWith {
    fn name(&self) -> &'static str {
        "BeginsWith"
    }

    fn param(&self) -> Option<&Param> {
        Some(&self.param)
    }
    fn evaluate(
        &self,
        t: &mut Transaction<'_>,
        _rule: &RuleWithActions,
        input: &[u8],
        rm: &mut RuleMessage<'_>,
    ) -> bool {
        let p = self.param.value(t);

        if input.len() < p.len() {
            false
        } else if input.starts_with(&p) {
            log_offset(rm, 0, p.len());
            true
        } else {
            false
        }
    }
}
