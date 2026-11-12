//! Port of `src/actions/skip_after.cc`, `src/actions/skip_after.h`.
//!
//! `skipAfter:MARKER` — skips the rules up to (and including) the
//! `SecMarker` of that name.

use crate::actions::action::{Action, ActionBase};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct SkipAfter {
    pub base: ActionBase,
    skip_name: String,
}

impl SkipAfter {
    pub fn new(action: &str) -> Self {
        let base = ActionBase::new(action);
        let skip_name = base.parser_payload.clone();
        SkipAfter { base, skip_name }
    }
}

impl Action for SkipAfter {
    crate::action_base_accessors!();

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, _rm: &mut RuleMessage<'_>) {
        crate::ms_dbg_a!(t, 5, "Setting skipAfter for: {}", self.skip_name);
        t.add_marker(&self.skip_name);
    }
}
