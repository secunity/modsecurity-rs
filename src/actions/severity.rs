//! `severity:N` or `severity:'CRITICAL'` — the severity of the rule match.

use crate::actions::action::Action;
use crate::actions::context::ActionContext;
use crate::utils::string::parse_digits;

#[derive(Debug)]
pub struct Severity {
    name: String,
    /// 0 (emergency) to 7 (debug).
    pub severity: u8,
}

impl Severity {
    /// The payload is a severity name or its number.
    pub fn new(name: &str, payload: &str) -> Result<Self, String> {
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
            _ => parse_digits(&a).ok_or_else(|| format!("Severity: The input \"{}\" is not a number.", a))?,
        };
        Ok(Severity { name: name.to_string(), severity })
    }
}

impl Action for Severity {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, cx: &mut ActionContext<'_, '_, '_>) {
        crate::ms_dbg!(
            cx,
            9,
            "This rule severity is: {} current transaction is: {}",
            self.severity,
            cx.highest_severity()
        );
        cx.set_severity(self.severity);
        cx.raise_highest_severity(self.severity);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::block::test_support::*;
    use crate::instance::ModSecurity;
    use crate::rule::message::RuleMessage;
    use crate::transaction::Transaction;

    fn sev(p: &str) -> Result<u8, String> {
        {
            let text = format!("severity:{}", p);
            let (name, payload) = crate::actions::action::name_and_payload(&text);
            Severity::new(name, payload)
        }
        .map(|s| s.severity)
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
        let s = Severity::new("severity", "2").unwrap();
        let r = rule(vec![]);
        let mut t = Transaction::new(&ms, &rules, None);
        let mut rm = RuleMessage::new(&r);
        assert_eq!((t.outcome.highest_severity, t.outcome.highest_severity_value()), (None, 255));
        s.evaluate(&mut ActionContext::new(&mut t, &r, &mut rm));
        assert_eq!(rm.severity, Some(2));
        assert_eq!(t.outcome.highest_severity, Some(2));
        assert!(has_log(&t, "This rule severity is: 2 current transaction is: 255"));
        let s5 = Severity::new("severity", "5").unwrap();
        s5.evaluate(&mut ActionContext::new(&mut t, &r, &mut rm));
        assert_eq!(rm.severity, Some(5));
        assert_eq!(t.outcome.highest_severity, Some(2));
    }
}
