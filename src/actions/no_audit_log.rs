//! `noauditlog` — the rule match does not make the transaction relevant for
//! the audit log.

use crate::actions::action::{Action, name_of};
use crate::actions::context::ActionContext;

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

    fn evaluate(&self, cx: &mut ActionContext<'_, '_, '_>) {
        cx.set_no_audit_log(true);
        cx.set_save_message(false);
    }
}
