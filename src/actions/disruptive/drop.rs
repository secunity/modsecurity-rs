//! Port of `src/actions/disruptive/drop.cc`, `src/actions/disruptive/drop.h`.
//!
//! `drop` — meant to close the connection; executes `deny` instead.

use crate::actions::action::{Action, ActionBase};
use crate::intervention::{free_log, strdup};
use crate::rule_message::{CLIENT_LOG_MESSAGE_INFO, RuleMessage};
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct Drop {
    pub base: ActionBase,
}

impl Drop {
    pub fn new(action: &str) -> Self {
        Drop { base: ActionBase::new(action) }
    }
}

impl Action for Drop {
    crate::action_base_accessors!();

    fn is_disruptive(&self) -> bool {
        true
    }

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, rm: &mut RuleMessage<'_>) -> bool {
        crate::ms_dbg_a!(t, 8, "Running action drop [executing deny instead of drop.]");
        if t.it.status == 200 {
            t.it.status = 403;
        }
        t.it.disruptive = 1;
        free_log(&mut t.it);
        rm.is_disruptive = true;
        let log = rm.log(t, CLIENT_LOG_MESSAGE_INFO, -1);
        t.it.log = strdup(&log);
        true
    }
}
