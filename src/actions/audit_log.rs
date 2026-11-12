//! Port of `src/actions/audit_log.cc`, `src/actions/audit_log.h`.
//!
//! `auditlog` — marks the transaction for audit logging.

use crate::actions::action::{Action, ActionBase};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct AuditLog {
    pub base: ActionBase,
}

impl AuditLog {
    pub fn new(action: &str) -> Self {
        AuditLog { base: ActionBase::new(action) }
    }
}

impl Action for AuditLog {
    crate::action_base_accessors!();

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, rm: &mut RuleMessage<'_>) {
        rm.no_audit_log = false;
        crate::ms_dbg_a!(t, 9, "Saving transaction to logs");
        rm.save_message = true;
    }
}
