//! `auditlog` — marks the transaction for audit logging.

use crate::actions::action::Action;
use crate::actions::context::ActionContext;

#[derive(Debug)]
pub struct AuditLog {
    name: String,
}

impl AuditLog {
    pub fn new(name: &str) -> Self {
        AuditLog { name: name.to_string() }
    }
}

impl Action for AuditLog {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, cx: &mut ActionContext<'_, '_, '_>) {
        cx.set_no_audit_log(false);
        crate::ms_dbg!(cx, 9, "Saving transaction to logs");
        cx.set_save_message(true);
    }
}
