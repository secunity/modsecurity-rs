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
        t: Option<&mut Transaction<'_>>,
        _rule: Option<&RuleWithActions>,
        input: &[u8],
        rm: Option<&mut RuleMessage<'_>>,
    ) -> bool {
        let p = self.base.string.as_ref().map_or_else(Vec::new, |s| s.evaluate(t.as_deref()));
        let offset = find(input, &p);

        let contains = offset.is_some();

        if let (Some(offset), Some(t)) = (offset, t) {
            if let Some(rm) = rm {
                log_offset(rm, offset, p.len());
            }
            t.matched.push(p);
        }

        contains
    }
}
