//! Port of `src/actions/data/status.cc`, `src/actions/data/status.h`.
//!
//! `status:N` — the HTTP status code used by the disruptive actions.

use crate::actions::action::{Action, ActionBase};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;
use crate::utils::string::stoi;

#[derive(Debug)]
pub struct Status {
    pub base: ActionBase,
    pub status: i32,
}

impl Status {
    pub fn new(action: &str) -> Self {
        Status { base: ActionBase::new(action), status: 0 }
    }
}

impl Action for Status {
    crate::action_base_accessors!();

    fn init(&mut self) -> Result<(), String> {
        // `std::stoi`: no digits or out of `int` range -> error.
        match stoi(self.base.parser_payload.as_bytes()).and_then(|v| i32::try_from(v).ok()) {
            Some(n) => {
                self.status = n;
                Ok(())
            }
            None => Err(format!("Not a valid number: {}", self.base.parser_payload)),
        }
    }

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, _rm: &mut RuleMessage<'_>) {
        t.intervention.status = self.status;
    }
}
