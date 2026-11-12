//! Port of `src/actions/skip.cc`, `src/actions/skip.h`.
//!
//! `skip:N` — skips the next N rules (or chains) when the rule matches.

use crate::actions::action::{Action, ActionBase};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;
use crate::utils::string::stoi;

#[derive(Debug)]
pub struct Skip {
    pub base: ActionBase,
    pub skip_next: i32,
}

impl Skip {
    pub fn new(action: &str) -> Self {
        Skip { base: ActionBase::new(action), skip_next: 0 }
    }
}

impl Action for Skip {
    crate::action_base_accessors!();

    fn init(&mut self) -> Result<(), String> {
        // `std::stoi`: no digits or out of `int` range -> error.
        match stoi(self.base.parser_payload.as_bytes()).and_then(|v| i32::try_from(v).ok()) {
            Some(n) => {
                self.skip_next = n;
                Ok(())
            }
            None => Err(format!("Skip: The input \"{}\" is not a number.", self.base.parser_payload)),
        }
    }

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, _rm: &mut RuleMessage<'_>) {
        crate::ms_dbg_a!(t, 5, "Skipping the next {} rules.", self.skip_next);
        t.skip_next = self.skip_next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::block::test_support::*;
    use crate::actions::skip_after::SkipAfter;
    use crate::modsecurity::ModSecurity;

    #[test]
    fn skip_and_skip_after() {
        assert_eq!(Skip::new("skip:a").init(), Err("Skip: The input \"a\" is not a number.".to_string()));
        let ms = ModSecurity::new();
        let rules = rules();
        let r = rule(vec![]);
        let mut t = Transaction::new(&ms, &rules, None);
        let mut rm = RuleMessage::new(&r);
        let mut s = Skip::new("skip:2");
        s.init().unwrap();
        s.evaluate(&r, &mut t, &mut rm);
        assert_eq!(t.skip_next, 2);
        assert!(has_log(&t, "Skipping the next 2 rules."));

        SkipAfter::new("skipAfter:END_HOST_CHECK").evaluate(&r, &mut t, &mut rm);
        assert_eq!(t.marker.as_deref(), Some("END_HOST_CHECK"));
        assert!(has_log(&t, "Setting skipAfter for: END_HOST_CHECK"));
    }
}
