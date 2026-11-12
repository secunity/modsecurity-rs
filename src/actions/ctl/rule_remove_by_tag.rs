//! Port of `src/actions/ctl/rule_remove_by_tag.cc`, `src/actions/ctl/rule_remove_by_tag.h`.
//!
//! `ctl:ruleRemoveByTag=TAG` — disables the rules carrying a tag for the
//! rest of the transaction.

use crate::actions::action::{Action, name_and_payload};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;

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

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, _rm: &mut RuleMessage<'_>) {
        t.rule_remove_by_tag.push(self.tag.clone());
    }
}
