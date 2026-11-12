//! Port of `src/actions/ctl/rule_remove_target_by_id.cc`, `src/actions/ctl/rule_remove_target_by_id.h`.
//!
//! `ctl:ruleRemoveTargetById=ID;VARIABLE` — removes a target from a rule
//! for the rest of the transaction.

use crate::actions::action::{Action, name_and_payload};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;
use crate::utils::string::{split_str, stoi};

#[derive(Debug)]
pub struct RuleRemoveTargetById {
    name: String,
    id: i32,
    target: String,
}

impl RuleRemoveTargetById {
    /// The payload is `ruleRemoveTargetById=<id>;<variable>`.
    pub fn new(action: &str) -> Result<Self, String> {
        let (name, payload) = name_and_payload(action);
        let Some((_, what)) = payload.split_once('=') else {
            return Err(format!("{} is not a valid 'ID;VARIABLE'", payload));
        };
        let mut param = split_str(what, ';').into_iter();
        let (Some(id), Some(target)) = (param.next(), param.next()) else {
            return Err(format!("{} is not a valid 'ID;VARIABLE'", what));
        };
        // `std::stoi`: no digits or out of `int` range -> error.
        let Some(id) = stoi(id.as_bytes()).and_then(|v| i32::try_from(v).ok()) else {
            return Err(format!("Not able to convert '{}' into a number", id));
        };
        Ok(RuleRemoveTargetById { name: name.to_string(), id, target })
    }
}

impl Action for RuleRemoveTargetById {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, _rm: &mut RuleMessage<'_>) {
        t.rule_remove_target_by_id.push((self.id, self.target.clone()));
    }
}
