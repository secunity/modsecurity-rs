//! `skip:N` — skips the next N rules (or chains) when the rule matches.

use crate::actions::action::{Action, name_and_payload};
use crate::actions::context::ActionContext;
use crate::utils::string::stoi;

#[derive(Debug)]
pub struct Skip {
    name: String,
    skip_next: i32,
}

impl Skip {
    pub fn new(action: &str) -> Result<Self, String> {
        let (name, payload) = name_and_payload(action);
        // `std::stoi`: no digits or out of `int` range -> error.
        let skip_next = stoi(payload.as_bytes())
            .and_then(|v| i32::try_from(v).ok())
            .ok_or_else(|| format!("Skip: The input \"{}\" is not a number.", payload))?;
        Ok(Skip { name: name.to_string(), skip_next })
    }
}

impl Action for Skip {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, cx: &mut ActionContext<'_, '_, '_>) {
        crate::act_dbg!(cx, 5, "Skipping the next {} rules.", self.skip_next);
        cx.skip_next(self.skip_next);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::block::test_support::*;
    use crate::actions::skip_after::SkipAfter;
    use crate::modsecurity::ModSecurity;
    use crate::rule_message::RuleMessage;
    use crate::transaction::Transaction;

    #[test]
    fn skip_and_skip_after() {
        assert_eq!(Skip::new("skip:a").unwrap_err(), "Skip: The input \"a\" is not a number.");
        let ms = ModSecurity::new();
        let rules = rules();
        let r = rule(vec![]);
        let mut t = Transaction::new(&ms, &rules, None);
        let mut rm = RuleMessage::new(&r);
        let s = Skip::new("skip:2").unwrap();
        s.evaluate(&mut ActionContext::new(&mut t, &r, &mut rm));
        assert_eq!(t.eval.skip_next, 2);
        assert!(has_log(&t, "Skipping the next 2 rules."));

        SkipAfter::new("skipAfter:END_HOST_CHECK").evaluate(&mut ActionContext::new(&mut t, &r, &mut rm));
        assert_eq!(t.eval.marker.as_deref(), Some("END_HOST_CHECK"));
        assert!(has_log(&t, "Setting skipAfter for: END_HOST_CHECK"));
    }
}
