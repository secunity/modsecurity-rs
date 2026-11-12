//! Port of `src/actions/no_log.cc`, `src/actions/no_log.h`.
//!
//! `nolog` — the rule match is not to be logged.

use crate::actions::action::{Action, name_of};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct NoLog {
    name: String,
}

impl NoLog {
    pub fn new(action: &str) -> Self {
        NoLog { name: name_of(action) }
    }
}

impl Action for NoLog {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, _rule: &RuleWithActions, _t: &mut Transaction<'_>, rm: &mut RuleMessage<'_>) {
        rm.save_message = false;
    }
}
