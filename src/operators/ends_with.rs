//! Port of `src/operators/ends_with.cc`, `src/operators/ends_with.h`.

use crate::operators::operator::{Operator, Param, log_offset};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct EndsWith {
    param: Param,
}

impl EndsWith {
    pub fn new(param: RunTimeString) -> Self {
        EndsWith { param: Param::expanded_in_message(param) }
    }
}

impl Operator for EndsWith {
    fn name(&self) -> &'static str {
        "EndsWith"
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
        let mut ret = false;
        let p = self.param.value(t);

        if input.len() >= p.len() {
            ret = input.ends_with(&p);
            if ret {
                log_offset(rm, input.len() - p.len(), p.len());
            }
        }

        ret
    }
}
