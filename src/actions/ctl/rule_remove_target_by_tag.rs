//! `ctl:ruleRemoveTargetByTag=TAG;VARIABLE` — removes a target from the
//! rules carrying a tag for the rest of the transaction.

use crate::actions::action::{Action, name_and_payload};
use crate::actions::context::ActionContext;
use crate::utils::string::split_str;

#[derive(Debug)]
pub struct RuleRemoveTargetByTag {
    name: String,
    tag: String,
    target: String,
}

impl RuleRemoveTargetByTag {
    /// The payload is `ruleRemoveTargetByTag=<tag>;<variable>`.
    pub fn new(action: &str) -> Result<Self, String> {
        let (name, payload) = name_and_payload(action);
        let Some((_, what)) = payload.split_once('=') else {
            return Err(format!("{} is not a valid 'TAG;VARIABLE'", payload));
        };
        let mut param = split_str(what, ';').into_iter();
        let (Some(tag), Some(target)) = (param.next(), param.next()) else {
            return Err(format!("{} is not a valid 'TAG;VARIABLE'", what));
        };
        Ok(RuleRemoveTargetByTag { name: name.to_string(), tag, target })
    }
}

impl Action for RuleRemoveTargetByTag {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, cx: &mut ActionContext<'_, '_, '_>) {
        cx.remove_target_by_tag(self.tag.clone(), self.target.clone());
    }
}
