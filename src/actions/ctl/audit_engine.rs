//! Port of `src/actions/ctl/audit_engine.cc`, `src/actions/ctl/audit_engine.h`.
//!
//! `ctl:auditEngine=On|Off|RelevantOnly` — overrides `SecAuditEngine` for
//! the transaction.

use crate::actions::action::{Action, ActionBase};
use crate::audit_log::audit_log::AuditLogStatus;
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct AuditEngine {
    pub base: ActionBase,
    pub audit_engine: AuditLogStatus,
}

impl AuditEngine {
    pub fn new(action: &str) -> Self {
        AuditEngine { base: ActionBase::new(action), audit_engine: AuditLogStatus::NotSet }
    }
}

impl Action for AuditEngine {
    crate::action_base_accessors!();

    fn init(&mut self) -> Result<(), String> {
        // The parser builds the payload as `auditengine=<value>`.
        let what = self.base.parser_payload.get(12..).unwrap_or("");
        self.audit_engine = match what {
            "on" => AuditLogStatus::On,
            "off" => AuditLogStatus::Off,
            "relevantonly" => AuditLogStatus::RelevantOnly,
            _ => {
                return Err(format!(
                    "Internal error. Expected: On, Off or RelevantOnly; got: {}",
                    self.base.parser_payload
                ));
            }
        };
        Ok(())
    }

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, _rm: &mut RuleMessage<'_>) {
        // C++ prints the numeric value of the enum.
        crate::ms_dbg_a!(
            t,
            8,
            "Setting SecAuditEngine to {} as requested by a ctl:auditEngine action",
            self.audit_engine as i32
        );
        t.ctl_audit_engine = self.audit_engine;
    }
}
