//! Port of `src/actions/ctl/audit_engine.cc`, `src/actions/ctl/audit_engine.h`.
//!
//! `ctl:auditEngine=On|Off|RelevantOnly` — overrides `SecAuditEngine` for
//! the transaction.

use crate::actions::action::Action;
use crate::audit_log::AuditLogStatus;
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct AuditEngine {
    status: AuditLogStatus,
}

impl AuditEngine {
    pub fn new(status: AuditLogStatus) -> Self {
        AuditEngine { status }
    }
}

impl Action for AuditEngine {
    fn name(&self) -> &str {
        "ctl"
    }

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, _rm: &mut RuleMessage<'_>) {
        // C++ prints the numeric value of the enum.
        crate::ms_dbg_a!(
            t,
            8,
            "Setting SecAuditEngine to {} as requested by a ctl:auditEngine action",
            self.status as i32
        );
        t.ctl_audit_engine = Some(self.status);
    }
}
