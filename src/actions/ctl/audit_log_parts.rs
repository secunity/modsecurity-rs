//! Port of `src/actions/ctl/audit_log_parts.cc`, `src/actions/ctl/audit_log_parts.h`.
//!
//! `ctl:auditLogParts=+E` / `=-E` — adds or removes audit log parts for
//! the transaction.

use crate::actions::action::{Action, ActionBase};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct AuditLogParts {
    pub base: ActionBase,
    /// 0: add the parts, 1: remove them.
    parts_action: i32,
    parts: String,
}

impl AuditLogParts {
    pub fn new(action: &str) -> Self {
        AuditLogParts { base: ActionBase::new(action), parts_action: 0, parts: String::new() }
    }
}

impl Action for AuditLogParts {
    crate::action_base_accessors!();

    fn init(&mut self) -> Result<(), String> {
        // The payload is `auditLogParts=<+|-><parts>`.
        let p = &self.base.parser_payload;
        let what = p.get(14..15).unwrap_or("");
        self.parts = p.get(15..).unwrap_or("").to_string();
        self.parts_action = if what == "+" { 0 } else { 1 };
        Ok(())
    }

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, _rm: &mut RuleMessage<'_>) -> bool {
        t.audit_log_modifier.push((self.parts_action, self.parts.clone()));
        true
    }
}
