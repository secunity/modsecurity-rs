//! Port of `src/actions/log.cc`, `src/actions/log.h`.
//!
//! `log` — the rule match is to be logged.

use crate::actions::action::{Action, ActionBase};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct Log {
    pub base: ActionBase,
}

impl Log {
    pub fn new(action: &str) -> Self {
        Log { base: ActionBase::new(action) }
    }
}

impl Action for Log {
    crate::action_base_accessors!();

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, rm: &mut RuleMessage<'_>) {
        crate::ms_dbg_a!(t, 9, "Saving transaction to logs");
        rm.save_message = true;
    }
}
