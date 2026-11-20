//! `phase:N` (or `request`/`response`/`logging`) — the phase in which the
//! rule runs (configuration time).

use crate::actions::action::{Action, Kind};
use crate::phases::Phases;
use crate::rule::Rule;

#[derive(Debug)]
pub struct Phase {
    name: String,
    pub phase: Phases,
}

impl Phase {
    /// The payload is a phase number (0 to 5) or `request`, `response` or
    /// `logging`.
    pub fn new(name: &str, payload: &str) -> Result<Self, String> {
        let phase = match payload.to_ascii_lowercase().as_str() {
            "0" => Phases::Connection,
            "1" => Phases::RequestHeaders,
            "2" | "request" => Phases::RequestBody,
            "3" => Phases::ResponseHeaders,
            "4" | "response" => Phases::ResponseBody,
            "5" | "logging" => Phases::Logging,
            _ => return Err(format!("Unknown phase: {}", payload)),
        };
        Ok(Phase { name: name.to_string(), phase })
    }
}

impl Action for Phase {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> Kind {
        Kind::Configuration
    }

    fn configure(&self, rule: &mut Rule) {
        rule.set_phase(self.phase);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::block::test_support::{RuleAction, rule};

    fn phase(p: &str) -> Result<Phases, String> {
        let a = {
            let text = format!("phase:{}", p);
            let (name, payload) = crate::actions::action::name_and_payload(&text);
            Phase::new(name, payload)
        }?;
        let phase = a.phase;
        assert_eq!(rule(vec![RuleAction::Phase(a)]).phase(), phase);
        Ok(phase)
    }

    #[test]
    fn init_and_configure() {
        assert_eq!(phase("0"), Ok(Phases::Connection));
        assert_eq!(phase("1"), Ok(Phases::RequestHeaders));
        assert_eq!(phase("2"), Ok(Phases::RequestBody));
        assert_eq!(phase("3"), Ok(Phases::ResponseHeaders));
        assert_eq!(phase("4"), Ok(Phases::ResponseBody));
        assert_eq!(phase("5"), Ok(Phases::Logging));
        assert_eq!(phase("REQUEST"), Ok(Phases::RequestBody));
        assert_eq!(phase("response"), Ok(Phases::ResponseBody));
        assert_eq!(phase("logging"), Ok(Phases::Logging));
        assert_eq!([Phases::Connection, Phases::RequestHeaders, Phases::Logging].map(Phases::number), [0, 1, 5]);
        // Anything else is refused. (An unknown name used to be accepted:
        // the rule was in no phase and never ran. C++ does the same, and
        // crashes on a number beyond `int`.)
        for unknown in ["foo", "6", "02", "+2", "2 ", "2147483648", "18446744073709551618", ""] {
            assert_eq!(phase(unknown), Err(format!("Unknown phase: {unknown}")), "{unknown:?}");
        }
    }
}
