//! Port of `src/actions/ctl/audit_log_parts.cc`, `src/actions/ctl/audit_log_parts.h`.
//!
//! `ctl:auditLogParts=+E` / `=-E` — adds or removes audit log parts for
//! the transaction.

use crate::actions::action::{Action, name_and_payload};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct AuditLogParts {
    name: String,
    /// 0: add the parts, 1: remove them.
    parts_action: i32,
    parts: String,
}

impl AuditLogParts {
    /// The payload is `auditLogParts=<+|-><parts>`.
    pub fn new(action: &str) -> Self {
        let (name, p) = name_and_payload(action);
        let sign = p.get(14..15).unwrap_or("");
        AuditLogParts {
            name: name.to_string(),
            parts_action: if sign == "+" { 0 } else { 1 },
            parts: p.get(15..).unwrap_or("").to_string(),
        }
    }
}

impl Action for AuditLogParts {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, _rm: &mut RuleMessage<'_>) {
        t.audit_log_modifier.push((self.parts_action, self.parts.clone()));
    }
}
