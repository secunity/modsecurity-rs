//! Port of `src/actions/ctl/rule_remove_target_by_id.cc`, `src/actions/ctl/rule_remove_target_by_id.h`.
//!
//! `ctl:ruleRemoveTargetById=ID;VARIABLE` — removes a target from a rule
//! for the rest of the transaction.

use crate::actions::action::{Action, ActionBase};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;
use crate::utils::string::{split_str, stoi};

#[derive(Debug)]
pub struct RuleRemoveTargetById {
    pub base: ActionBase,
    pub id: i32,
    pub target: String,
}

impl RuleRemoveTargetById {
    pub fn new(action: &str) -> Self {
        RuleRemoveTargetById { base: ActionBase::new(action), id: 0, target: String::new() }
    }
}

impl Action for RuleRemoveTargetById {
    crate::action_base_accessors!();

    fn init(&mut self) -> Result<(), String> {
        let payload = &self.base.parser_payload;
        let Some(pos) = payload.find('=') else {
            return Err(format!("{} is not a valid 'ID;VARIABLE'", payload));
        };
        let what = &payload[pos + 1..];
        let param = split_str(what, ';');
        if param.len() < 2 {
            return Err(format!("{} is not a valid 'ID;VARIABLE'", what));
        }
        // `std::stoi`: no digits or out of `int` range -> error.
        let Some(id) = stoi(param[0].as_bytes()).and_then(|v| i32::try_from(v).ok()) else {
            return Err(format!("Not able to convert '{}' into a number", param[0]));
        };
        self.id = id;
        self.target = param[1].clone();
        Ok(())
    }

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, _rm: &mut RuleMessage<'_>) -> bool {
        t.rule_remove_target_by_id.push((self.id, self.target.clone()));
        true
    }
}
