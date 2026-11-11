//! Port of `src/actions/no_log.cc`, `src/actions/no_log.h`.
//!
//! `nolog` — the rule match is not to be logged.

use crate::actions::action::{Action, ActionBase};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct NoLog {
    pub base: ActionBase,
}

impl NoLog {
    pub fn new(action: &str) -> Self {
        NoLog { base: ActionBase::new(action) }
    }
}

impl Action for NoLog {
    crate::action_base_accessors!();

    fn evaluate(&self, _rule: &RuleWithActions, _t: &mut Transaction<'_>, rm: &mut RuleMessage<'_>) -> bool {
        rm.save_message = false;
        true
    }
}
