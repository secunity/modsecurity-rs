//! Port of `src/actions/severity.cc`, `src/actions/severity.h`.
//!
//! `severity:N` or `severity:'CRITICAL'` — the severity of the rule match.

use crate::actions::action::{Action, ActionBase};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;
use crate::utils::string::stoi;

#[derive(Debug)]
pub struct Severity {
    pub base: ActionBase,
    pub severity: i32,
}

impl Severity {
    pub fn new(action: &str) -> Self {
        Severity { base: ActionBase::new(action), severity: 0 }
    }
}

impl Action for Severity {
    crate::action_base_accessors!();

    fn init(&mut self) -> Result<(), String> {
        let a = self.base.parser_payload.to_ascii_lowercase();
        self.severity = match a.as_str() {
            "emergency" => 0,
            "alert" => 1,
            "critical" => 2,
            "error" => 3,
            "warning" => 4,
            "notice" => 5,
            "info" => 6,
            "debug" => 7,
            _ => match stoi(a.as_bytes()).and_then(|v| i32::try_from(v).ok()) {
                Some(n) => n,
                None => return Err(format!("Severity: The input \"{}\" is not a number.", a)),
            },
        };
        Ok(())
    }

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, rm: &mut RuleMessage<'_>) {
        crate::ms_dbg_a!(
            t,
            9,
            "This rule severity is: {} current transaction is: {}",
            self.severity,
            t.highest_severity_action
        );
        rm.severity = self.severity;
        if t.highest_severity_action > self.severity {
            t.highest_severity_action = self.severity;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::block::test_support::*;
    use crate::modsecurity::ModSecurity;

    fn sev(p: &str) -> Result<i32, String> {
        let mut s = Severity::new(&format!("severity:{}", p));
        s.init().map(|_| s.severity)
    }

    #[test]
    fn init() {
        assert_eq!(sev("CRITICAL"), Ok(2));
        assert_eq!(sev("'Warning'"), Ok(4));
        assert_eq!(sev("debug"), Ok(7));
        assert_eq!(sev("3"), Ok(3));
        assert_eq!(sev("Foo"), Err("Severity: The input \"foo\" is not a number.".to_string()));
    }

    #[test]
    fn evaluate() {
        let ms = ModSecurity::new();
        let rules = rules();
        let mut s = Severity::new("severity:2");
        s.init().unwrap();
        let r = rule(vec![]);
        let mut t = Transaction::new(&ms, &rules, None);
        let mut rm = RuleMessage::new(&r);
        let before = t.highest_severity_action;
        s.evaluate(&r, &mut t, &mut rm);
        assert_eq!(rm.severity, 2);
        assert_eq!(t.highest_severity_action, 2.min(before));
        assert!(has_log(&t, &format!("This rule severity is: 2 current transaction is: {}", before)));
        let mut s5 = Severity::new("severity:5");
        s5.init().unwrap();
        s5.evaluate(&r, &mut t, &mut rm);
        assert_eq!(rm.severity, 5);
        assert_eq!(t.highest_severity_action, 2.min(before));
    }
}
