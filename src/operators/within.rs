//! Port of `src/operators/within.cc`, `src/operators/within.h`.

use crate::operators::operator::{Operator, Param, log_offset};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;
use crate::utils::string::find;

#[derive(Debug)]
pub struct Within {
    param: Param,
}

impl Within {
    pub fn new(param: RunTimeString) -> Self {
        Within { param: Param::expanded_in_message(param) }
    }
}

impl Operator for Within {
    fn name(&self) -> &'static str {
        "Within"
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
        let param_target = self.param.value(t);

        if input.is_empty() {
            return true;
        }

        let pos = find(&param_target, input);
        if let Some(pos) = pos {
            log_offset(rm, pos, input.len());
        }

        pos.is_some()
    }
}
