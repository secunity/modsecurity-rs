//! Port of `src/operators/ends_with.cc`, `src/operators/ends_with.h`.

use crate::operators::operator::{Operator, OperatorBase, log_offset};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct EndsWith {
    pub base: OperatorBase,
}

impl EndsWith {
    pub fn new(param: RunTimeString) -> Self {
        let mut base = OperatorBase::with_string("EndsWith", param);
        base.could_contain_macro = true;
        EndsWith { base }
    }
}

impl Operator for EndsWith {
    crate::operator_base_accessors!();
    fn evaluate(
        &self,
        t: &mut Transaction<'_>,
        _rule: &RuleWithActions,
        input: &[u8],
        rm: &mut RuleMessage<'_>,
    ) -> bool {
        let mut ret = false;
        let p = self.base.param_value(t);

        if input.len() >= p.len() {
            ret = input.ends_with(&p);
            if ret {
                log_offset(rm, input.len() - p.len(), p.len());
            }
        }

        ret
    }
}
