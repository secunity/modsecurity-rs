//! `ctl:ruleRemoveTargetById=ID;VARIABLE` — removes a target from a rule
//! for the rest of the transaction.

use crate::actions::action::Action;
use crate::actions::context::ActionContext;
use crate::utils::string::{split_str, stoi};

#[derive(Debug)]
pub struct RuleRemoveTargetById {
    name: String,
    id: i32,
    target: String,
}

impl RuleRemoveTargetById {
    /// The payload is `ruleRemoveTargetById=<id>;<variable>`.
    pub fn new(name: &str, payload: &str) -> Result<Self, String> {
        let Some((_, what)) = payload.split_once('=') else {
            return Err(format!("{} is not a valid 'ID;VARIABLE'", payload));
        };
        let mut param = split_str(what, ';').into_iter();
        let (Some(id), Some(target)) = (param.next(), param.next()) else {
            return Err(format!("{} is not a valid 'ID;VARIABLE'", what));
        };
        // `std::stoi`: no digits or out of `int` range -> error.
        let Some(id) = stoi(id.as_bytes()) else {
            return Err(format!("Not able to convert '{}' into a number", id));
        };
        Ok(RuleRemoveTargetById { name: name.to_string(), id, target })
    }
}

impl Action for RuleRemoveTargetById {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, cx: &mut ActionContext<'_, '_, '_>) {
        cx.remove_target_by_id(self.id, self.target.clone());
    }
}
