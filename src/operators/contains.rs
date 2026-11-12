//! Port of `src/operators/contains.cc`, `src/operators/contains.h`.

use crate::operators::operator::{Operator, OperatorBase, log_offset};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;
use crate::utils::string::find;

#[derive(Debug)]
pub struct Contains {
    pub base: OperatorBase,
}

impl Contains {
    pub fn new(param: RunTimeString) -> Self {
        Contains { base: OperatorBase::with_string("Contains", param) }
    }
}

impl Operator for Contains {
    crate::operator_base_accessors!();
    fn evaluate(
        &self,
        t: &mut Transaction<'_>,
        _rule: &RuleWithActions,
        input: &[u8],
        rm: &mut RuleMessage<'_>,
    ) -> bool {
        let p = self.base.param_value(t);
        let offset = find(input, &p);

        let contains = offset.is_some();

        if let Some(offset) = offset {
            log_offset(rm, offset, p.len());
            t.matched.push(p.into_owned());
        }

        contains
    }
}
