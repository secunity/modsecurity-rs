//! Port of `src/actions/severity.cc`, `src/actions/severity.h`.
//!
//! `severity:N` or `severity:'CRITICAL'` — the severity of the rule match.

use crate::actions::action::{Action, name_and_payload};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;
use crate::utils::string::stoi;

#[derive(Debug)]
pub struct Severity {
    name: String,
    pub severity: i32,
}

impl Severity {
    /// The payload is a severity name or its number.
    pub fn new(action: &str) -> Result<Self, String> {
        let (name, payload) = name_and_payload(action);
        let a = payload.to_ascii_lowercase();
        let severity = match a.as_str() {
            "emergency" => 0,
            "alert" => 1,
            "critical" => 2,
            "error" => 3,
            "warning" => 4,
            "notice" => 5,
            "info" => 6,
            "debug" => 7,
            _ => stoi(a.as_bytes())
                .and_then(|v| i32::try_from(v).ok())
                .ok_or_else(|| format!("Severity: The input \"{}\" is not a number.", a))?,
        };
        Ok(Severity { name: name.to_string(), severity })
    }
}

impl Action for Severity {
    fn name(&self) -> &str {
        &self.name
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
        Severity::new(&format!("severity:{}", p)).map(|s| s.severity)
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
        let s = Severity::new("severity:2").unwrap();
        let r = rule(vec![]);
        let mut t = Transaction::new(&ms, &rules, None);
        let mut rm = RuleMessage::new(&r);
        let before = t.highest_severity_action;
        s.evaluate(&r, &mut t, &mut rm);
        assert_eq!(rm.severity, 2);
        assert_eq!(t.highest_severity_action, 2.min(before));
        assert!(has_log(&t, &format!("This rule severity is: 2 current transaction is: {}", before)));
        let s5 = Severity::new("severity:5").unwrap();
        s5.evaluate(&r, &mut t, &mut rm);
        assert_eq!(rm.severity, 5);
        assert_eq!(t.highest_severity_action, 2.min(before));
    }
}
