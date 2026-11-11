//! Port of `src/actions/ctl/rule_remove_by_tag.cc`, `src/actions/ctl/rule_remove_by_tag.h`.
//!
//! `ctl:ruleRemoveByTag=TAG` — disables the rules carrying a tag for the
//! rest of the transaction.

use crate::actions::action::{Action, ActionBase};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct RuleRemoveByTag {
    pub base: ActionBase,
    pub tag: String,
}

impl RuleRemoveByTag {
    pub fn new(action: &str) -> Self {
        RuleRemoveByTag { base: ActionBase::new(action), tag: String::new() }
    }
}

impl Action for RuleRemoveByTag {
    crate::action_base_accessors!();

    fn init(&mut self) -> Result<(), String> {
        let payload = &self.base.parser_payload;
        let Some(pos) = payload.find('=') else {
            return Err(format!("{} is not a valid tag", payload));
        };
        self.tag = payload[pos + 1..].to_string();
        Ok(())
    }

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, _rm: &mut RuleMessage<'_>) -> bool {
        t.rule_remove_by_tag.push(self.tag.clone());
        true
    }
}
