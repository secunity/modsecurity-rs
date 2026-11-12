//! Port of `src/actions/log_data.cc`, `src/actions/log_data.h`.
//!
//! `logdata:'...'` — data (with macro expansion) logged with the rule
//! match.

use crate::actions::action::Action;
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct LogData {
    pub string: RunTimeString,
}

impl LogData {
    pub fn with_rts(z: RunTimeString) -> Self {
        LogData { string: z }
    }

    pub fn data(&self, t: &Transaction<'_>) -> Vec<u8> {
        self.string.evaluate(Some(t))
    }
}

impl Action for LogData {
    fn name(&self) -> &str {
        "logdata"
    }

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, rm: &mut RuleMessage<'_>) {
        rm.data = self.data(t);
    }
}
