//! The `@strmatch` operator: matches when the parameter occurs anywhere in
//! the input.

use crate::operators::operator::{Operator, Param};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;
use crate::utils::string::find;

#[derive(Debug)]
pub struct StrMatch {
    param: Param,
}

impl StrMatch {
    pub fn new(param: RunTimeString) -> Self {
        StrMatch { param: Param::expanded_in_message(param) }
    }
}

impl Operator for StrMatch {
    fn name(&self) -> &'static str {
        "StrMatch"
    }

    fn param(&self) -> Option<&Param> {
        Some(&self.param)
    }
    fn evaluate(
        &self,
        t: &mut Transaction<'_>,
        _rule: &RuleWithActions,
        input: &[u8],
        _rm: &mut RuleMessage<'_>,
    ) -> bool {
        let p = self.param.value(t);
        find(input, &p).is_some()
    }
}
