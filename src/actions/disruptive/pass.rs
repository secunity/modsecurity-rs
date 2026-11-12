//! Port of `src/actions/disruptive/pass.cc`, `src/actions/disruptive/pass.h`.
//!
//! `pass` — continues with the next rule; discards any pending
//! intervention.

use crate::actions::action::{Action, name_of};
use crate::intervention::Intervention;
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct Pass {
    name: String,
}

impl Pass {
    pub fn new(action: &str) -> Self {
        Pass { name: name_of(action) }
    }
}

impl Action for Pass {
    fn name(&self) -> &str {
        &self.name
    }

    fn is_disruptive(&self) -> bool {
        true
    }

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, _rm: &mut RuleMessage<'_>) {
        // intervention::free + reset: drops the url and log too.
        t.intervention = Intervention::default();
        crate::ms_dbg_a!(t, 8, "Running action pass");
    }
}
