//! Port of `src/actions/phase.cc`, `src/actions/phase.h`.
//!
//! `phase:N` (or `request`/`response`/`logging`) — the phase in which the
//! rule runs (configuration time).

use crate::actions::action::{Action, Kind, name_and_payload};
use crate::modsecurity::Phases;
use crate::rule_with_actions::RuleWithActions;
use crate::utils::string::stoi;

#[derive(Debug)]
pub struct Phase {
    name: String,
    /// The phase; `None` for an unknown name (see [`Phase::new`]).
    pub phase: Option<Phases>,
    /// The SecLang phase number (0..5).
    pub sec_rules_phase: i32,
}

impl Phase {
    /// The payload is a phase number (0..5) or `request`, `response` or
    /// `logging`.
    pub fn new(action: &str) -> Result<Self, String> {
        let (name, payload) = name_and_payload(action);
        // `std::stoi` throws for non numbers and for values out of the
        // `int` range.
        let (phase, sec_rules_phase) = match stoi(payload.as_bytes()).and_then(|v| i32::try_from(v).ok()) {
            Some(0) => (Some(Phases::Connection), 0),
            Some(1) => (Some(Phases::RequestHeaders), 1),
            Some(2) => (Some(Phases::RequestBody), 2),
            Some(3) => (Some(Phases::ResponseHeaders), 3),
            Some(4) => (Some(Phases::ResponseBody), 4),
            Some(5) => (Some(Phases::Logging), 5),
            Some(_) => return Err(format!("Unknown phase: {}", payload)),
            None => match payload.to_ascii_lowercase().as_str() {
                "request" => (Some(Phases::RequestBody), 2),
                "response" => (Some(Phases::ResponseBody), 4),
                "logging" => (Some(Phases::Logging), 5),
                // Quirk kept from C++: an unknown name is not reported and
                // leaves the rule without a phase (C++: phase -1), so it
                // never runs.
                _ => (None, 0),
            },
        };
        Ok(Phase { name: name.to_string(), phase, sec_rules_phase })
    }
}

impl Action for Phase {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> Kind {
        Kind::Configuration
    }

    fn configure(&self, rule: &mut RuleWithActions) {
        rule.set_phase(self.phase);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::block::test_support::{RuleAction, rule};

    fn phase(p: &str) -> Result<(Option<Phases>, i32), String> {
        let a = Phase::new(&format!("phase:{}", p))?;
        let r = (a.phase, a.sec_rules_phase);
        assert_eq!(rule(vec![RuleAction::Phase(a)]).phase(), r.0);
        Ok(r)
    }

    #[test]
    fn init_and_configure() {
        assert_eq!(phase("0"), Ok((Some(Phases::Connection), 0)));
        assert_eq!(phase("1"), Ok((Some(Phases::RequestHeaders), 1)));
        assert_eq!(phase("2"), Ok((Some(Phases::RequestBody), 2)));
        assert_eq!(phase("3"), Ok((Some(Phases::ResponseHeaders), 3)));
        assert_eq!(phase("4"), Ok((Some(Phases::ResponseBody), 4)));
        assert_eq!(phase("5"), Ok((Some(Phases::Logging), 5)));
        assert_eq!(phase("REQUEST"), Ok((Some(Phases::RequestBody), 2)));
        assert_eq!(phase("response"), Ok((Some(Phases::ResponseBody), 4)));
        assert_eq!(phase("logging"), Ok((Some(Phases::Logging), 5)));
        // C++ quirk: an unknown name is accepted, without a phase.
        assert_eq!(phase("foo"), Ok((None, 0)));
        assert_eq!(phase("6"), Err("Unknown phase: 6".to_string()));
    }
}
