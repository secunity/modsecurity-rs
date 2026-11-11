//! Port of `src/actions/phase.cc`, `src/actions/phase.h`.
//!
//! `phase:N` (or `request`/`response`/`logging`) — the phase in which the
//! rule runs (configuration time).

use crate::actions::action::{Action, ActionBase, Kind};
use crate::modsecurity::Phases;
use crate::rule_with_actions::RuleWithActions;
use crate::utils::string::stoi;

#[derive(Debug)]
pub struct Phase {
    pub base: ActionBase,
    /// The internal phase (`Phases` value).
    pub phase: i32,
    /// The SecLang phase number (0..5).
    pub sec_rules_phase: i32,
}

impl Phase {
    pub fn new(action: &str) -> Self {
        Phase { base: ActionBase::with_kind(action, Kind::ConfigurationKind), phase: 0, sec_rules_phase: 0 }
    }
}

impl Action for Phase {
    crate::action_base_accessors!();

    fn init(&mut self) -> Result<(), String> {
        let a = self.base.parser_payload.to_ascii_lowercase();
        self.phase = -1;

        // `std::stoi` throws for non numbers and for values out of the
        // `int` range.
        match stoi(self.base.parser_payload.as_bytes()).and_then(|v| i32::try_from(v).ok()) {
            Some(n) => {
                let (phase, sec_rules_phase) = match n {
                    0 => (Phases::ConnectionPhase, 0),
                    1 => (Phases::RequestHeadersPhase, 1),
                    2 => (Phases::RequestBodyPhase, 2),
                    3 => (Phases::ResponseHeadersPhase, 3),
                    4 => (Phases::ResponseBodyPhase, 4),
                    5 => (Phases::LoggingPhase, 5),
                    _ => {
                        self.phase = n;
                        return Err(format!("Unknown phase: {}", self.base.parser_payload));
                    }
                };
                self.phase = phase as i32;
                self.sec_rules_phase = sec_rules_phase;
            }
            None => {
                // Quirk kept from C++: an unknown name is not reported and
                // leaves the phase at -1.
                if a == "request" {
                    self.phase = Phases::RequestBodyPhase as i32;
                    self.sec_rules_phase = 2;
                } else if a == "response" {
                    self.phase = Phases::ResponseBodyPhase as i32;
                    self.sec_rules_phase = 4;
                } else if a == "logging" {
                    self.phase = Phases::LoggingPhase as i32;
                    self.sec_rules_phase = 5;
                }
            }
        }
        Ok(())
    }

    fn configure(&self, rule: &mut RuleWithActions) -> bool {
        rule.set_phase(self.phase);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::block::test_support::rule;

    fn phase(p: &str) -> Result<(i32, i32), String> {
        let mut a = Phase::new(&format!("phase:{}", p));
        a.init()?;
        let r = (a.phase, a.sec_rules_phase);
        assert_eq!(rule(vec![Box::new(a)]).get_phase(), r.0);
        Ok(r)
    }

    #[test]
    fn init_and_configure() {
        assert_eq!(phase("0"), Ok((Phases::ConnectionPhase as i32, 0)));
        assert_eq!(phase("1"), Ok((Phases::RequestHeadersPhase as i32, 1)));
        assert_eq!(phase("2"), Ok((Phases::RequestBodyPhase as i32, 2)));
        assert_eq!(phase("3"), Ok((Phases::ResponseHeadersPhase as i32, 3)));
        assert_eq!(phase("4"), Ok((Phases::ResponseBodyPhase as i32, 4)));
        assert_eq!(phase("5"), Ok((Phases::LoggingPhase as i32, 5)));
        assert_eq!(phase("REQUEST"), Ok((Phases::RequestBodyPhase as i32, 2)));
        assert_eq!(phase("response"), Ok((Phases::ResponseBodyPhase as i32, 4)));
        assert_eq!(phase("logging"), Ok((Phases::LoggingPhase as i32, 5)));
        // C++ quirk: an unknown name is accepted with phase -1.
        assert_eq!(phase("foo"), Ok((-1, 0)));
        assert_eq!(phase("6"), Err("Unknown phase: 6".to_string()));
    }
}
