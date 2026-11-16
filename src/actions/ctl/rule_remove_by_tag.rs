//! `ctl:ruleRemoveByTag=TAG` — disables the rules carrying a tag for the
//! rest of the transaction.

use crate::actions::action::{Action, name_and_payload};
use crate::actions::context::ActionContext;

#[derive(Debug)]
pub struct RuleRemoveByTag {
    name: String,
    tag: String,
}

impl RuleRemoveByTag {
    /// The payload is `ruleRemoveByTag=<tag>`.
    pub fn new(action: &str) -> Result<Self, String> {
        let (name, payload) = name_and_payload(action);
        let Some((_, tag)) = payload.split_once('=') else {
            return Err(format!("{} is not a valid tag", payload));
        };
        Ok(RuleRemoveByTag { name: name.to_string(), tag: tag.to_string() })
    }
}

impl Action for RuleRemoveByTag {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, cx: &mut ActionContext<'_, '_, '_>) {
        cx.remove_rules_by_tag(self.tag.clone());
    }
}
