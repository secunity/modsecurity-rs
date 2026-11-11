//! Port of `src/actions/ctl/rule_remove_target_by_tag.cc`, `src/actions/ctl/rule_remove_target_by_tag.h`.
//!
//! `ctl:ruleRemoveTargetByTag=TAG;VARIABLE` — removes a target from the
//! rules carrying a tag for the rest of the transaction.

use crate::actions::action::{Action, ActionBase};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;
use crate::utils::string::split_str;

#[derive(Debug)]
pub struct RuleRemoveTargetByTag {
    pub base: ActionBase,
    pub tag: String,
    pub target: String,
}

impl RuleRemoveTargetByTag {
    pub fn new(action: &str) -> Self {
        RuleRemoveTargetByTag { base: ActionBase::new(action), tag: String::new(), target: String::new() }
    }
}

impl Action for RuleRemoveTargetByTag {
    crate::action_base_accessors!();

    fn init(&mut self) -> Result<(), String> {
        let payload = &self.base.parser_payload;
        let Some(pos) = payload.find('=') else {
            return Err(format!("{} is not a valid 'TAG;VARIABLE'", payload));
        };
        let what = &payload[pos + 1..];
        let param = split_str(what, ';');
        if param.len() < 2 {
            return Err(format!("{} is not a valid 'TAG;VARIABLE'", what));
        }
        self.tag = param[0].clone();
        self.target = param[1].clone();
        Ok(())
    }

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, _rm: &mut RuleMessage<'_>) -> bool {
        t.rule_remove_target_by_tag.push((self.tag.clone(), self.target.clone()));
        true
    }
}
