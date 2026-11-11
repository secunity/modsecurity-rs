//! Port of `src/actions/log_data.cc`, `src/actions/log_data.h`.
//!
//! `logdata:'...'` — data (with macro expansion) logged with the rule
//! match.

use crate::actions::action::{Action, ActionBase};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct LogData {
    pub base: ActionBase,
    pub string: RunTimeString,
}

impl LogData {
    pub fn with_rts(z: RunTimeString) -> Self {
        LogData { base: ActionBase::new("logdata"), string: z }
    }

    pub fn data(&self, t: &Transaction<'_>) -> Vec<u8> {
        self.string.evaluate(Some(t))
    }
}

impl Action for LogData {
    crate::action_base_accessors!();

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, rm: &mut RuleMessage<'_>) -> bool {
        rm.data = self.data(t);
        true
    }
}
