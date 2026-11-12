//! Port of `src/actions/no_audit_log.cc`, `src/actions/no_audit_log.h`.
//!
//! `noauditlog` — the rule match does not make the transaction relevant for
//! the audit log.

use crate::actions::action::{Action, name_of};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct NoAuditLog {
    name: String,
}

impl NoAuditLog {
    pub fn new(action: &str) -> Self {
        NoAuditLog { name: name_of(action) }
    }
}

impl Action for NoAuditLog {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, _rule: &RuleWithActions, _t: &mut Transaction<'_>, rm: &mut RuleMessage<'_>) {
        rm.no_audit_log = true;
        rm.save_message = false;
    }
}
