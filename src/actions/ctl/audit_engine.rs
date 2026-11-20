//! `ctl:auditEngine=On|Off|RelevantOnly` — overrides `SecAuditEngine` for
//! the transaction.

use crate::actions::action::Action;
use crate::actions::context::ActionContext;
use crate::audit_log::AuditLogStatus;

#[derive(Debug)]
pub struct AuditEngine {
    status: AuditLogStatus,
}

impl AuditEngine {
    pub fn new(status: AuditLogStatus) -> Self {
        AuditEngine { status }
    }

    /// The setting the action gives the transaction.
    pub fn status(&self) -> AuditLogStatus {
        self.status
    }
}

impl Action for AuditEngine {
    fn name(&self) -> &str {
        "ctl"
    }

    fn evaluate(&self, cx: &mut ActionContext<'_, '_, '_>) {
        // The debug log shows the setting as its number.
        crate::ms_dbg!(
            cx,
            8,
            "Setting SecAuditEngine to {} as requested by a ctl:auditEngine action",
            self.status as i32
        );
        cx.set_audit_engine(self.status);
    }
}
