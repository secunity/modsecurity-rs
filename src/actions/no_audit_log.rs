//! Port of `src/actions/no_audit_log.cc`, `src/actions/no_audit_log.h`.
//!
//! `noauditlog` — the rule match does not make the transaction relevant for
//! the audit log.

use crate::actions::action::{Action, ActionBase};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct NoAuditLog {
    pub base: ActionBase,
}

impl NoAuditLog {
    pub fn new(action: &str) -> Self {
        NoAuditLog { base: ActionBase::new(action) }
    }
}

impl Action for NoAuditLog {
    crate::action_base_accessors!();

    fn evaluate(&self, _rule: &RuleWithActions, _t: &mut Transaction<'_>, rm: &mut RuleMessage<'_>) {
        rm.no_audit_log = true;
        rm.save_message = false;
    }
}
