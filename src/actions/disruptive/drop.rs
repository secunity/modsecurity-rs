//! Port of `src/actions/disruptive/drop.cc`, `src/actions/disruptive/drop.h`.
//!
//! `drop` — meant to close the connection; executes `deny` instead.

use crate::actions::action::{Action, name_of};
use crate::rule_message::{CLIENT_LOG_MESSAGE_INFO, RuleMessage};
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct Drop {
    name: String,
}

impl Drop {
    pub fn new(action: &str) -> Self {
        Drop { name: name_of(action) }
    }
}

impl Action for Drop {
    fn name(&self) -> &str {
        &self.name
    }

    fn is_disruptive(&self) -> bool {
        true
    }

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, rm: &mut RuleMessage<'_>) {
        crate::ms_dbg_a!(t, 8, "Running action drop [executing deny instead of drop.]");
        if t.intervention.status == 200 {
            t.intervention.status = 403;
        }
        t.intervention.disruptive = true;
        rm.is_disruptive = true;
        t.intervention.log = Some(rm.log(t, CLIENT_LOG_MESSAGE_INFO, -1));
    }
}
