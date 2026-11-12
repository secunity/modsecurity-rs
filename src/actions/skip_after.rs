//! Port of `src/actions/skip_after.cc`, `src/actions/skip_after.h`.
//!
//! `skipAfter:MARKER` — skips the rules up to (and including) the
//! `SecMarker` of that name.

use crate::actions::action::{Action, name_and_payload};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct SkipAfter {
    name: String,
    skip_name: String,
}

impl SkipAfter {
    pub fn new(action: &str) -> Self {
        let (name, skip_name) = name_and_payload(action);
        SkipAfter { name: name.to_string(), skip_name: skip_name.to_string() }
    }
}

impl Action for SkipAfter {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, _rm: &mut RuleMessage<'_>) {
        crate::ms_dbg_a!(t, 5, "Setting skipAfter for: {}", self.skip_name);
        t.add_marker(&self.skip_name);
    }
}
