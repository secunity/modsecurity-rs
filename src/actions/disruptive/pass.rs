//! Port of `src/actions/disruptive/pass.cc`, `src/actions/disruptive/pass.h`.
//!
//! `pass` — continues with the next rule; discards any pending
//! intervention.

use crate::actions::action::{Action, ActionBase};
use crate::intervention;
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct Pass {
    pub base: ActionBase,
}

impl Pass {
    pub fn new(action: &str) -> Self {
        Pass { base: ActionBase::new(action) }
    }
}

impl Action for Pass {
    crate::action_base_accessors!();

    fn is_disruptive(&self) -> bool {
        true
    }

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, _rm: &mut RuleMessage<'_>) -> bool {
        intervention::free(&mut t.it);
        intervention::reset(&mut t.it);
        crate::ms_dbg_a!(t, 8, "Running action pass");
        true
    }
}
