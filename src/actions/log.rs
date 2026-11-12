//! Port of `src/actions/log.cc`, `src/actions/log.h`.
//!
//! `log` — the rule match is to be logged.

use crate::actions::action::{Action, name_of};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct Log {
    name: String,
}

impl Log {
    pub fn new(action: &str) -> Self {
        Log { name: name_of(action) }
    }
}

impl Action for Log {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, rm: &mut RuleMessage<'_>) {
        crate::ms_dbg_a!(t, 9, "Saving transaction to logs");
        rm.save_message = true;
    }
}
