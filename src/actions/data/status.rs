//! Port of `src/actions/data/status.cc`, `src/actions/data/status.h`.
//!
//! `status:N` — the HTTP status code used by the disruptive actions.

use crate::actions::action::{Action, name_and_payload};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;
use crate::utils::string::stoi;

#[derive(Debug)]
pub struct Status {
    name: String,
    status: i32,
}

impl Status {
    pub fn new(action: &str) -> Result<Self, String> {
        let (name, payload) = name_and_payload(action);
        // `std::stoi`: no digits or out of `int` range -> error.
        let status = stoi(payload.as_bytes())
            .and_then(|v| i32::try_from(v).ok())
            .ok_or_else(|| format!("Not a valid number: {}", payload))?;
        Ok(Status { name: name.to_string(), status })
    }
}

impl Action for Status {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, _rm: &mut RuleMessage<'_>) {
        t.intervention.status = self.status;
    }
}
