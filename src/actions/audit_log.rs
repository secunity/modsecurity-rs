//! `auditlog` — marks the transaction for audit logging.

use crate::actions::action::{Action, name_of};
use crate::actions::context::ActionContext;

#[derive(Debug)]
pub struct AuditLog {
    name: String,
}

impl AuditLog {
    pub fn new(action: &str) -> Self {
        AuditLog { name: name_of(action) }
    }
}

impl Action for AuditLog {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, cx: &mut ActionContext<'_, '_, '_>) {
        cx.set_no_audit_log(false);
        crate::act_dbg!(cx, 9, "Saving transaction to logs");
        cx.set_save_message(true);
    }
}
