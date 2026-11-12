//! Port of `src/actions/accuracy.cc`, `src/actions/accuracy.h`.
//!
//! `accuracy:N` — the accuracy level of the rule (configuration time).

use crate::actions::action::{Action, Kind, name_and_payload};
use crate::rule_with_actions::RuleWithActions;
use crate::utils::string::stoi;

#[derive(Debug)]
pub struct Accuracy {
    name: String,
    accuracy: i32,
}

impl Accuracy {
    pub fn new(action: &str) -> Result<Self, String> {
        let (name, payload) = name_and_payload(action);
        // `std::stoi`: no digits or out of `int` range -> error.
        let accuracy = stoi(payload.as_bytes())
            .and_then(|v| i32::try_from(v).ok())
            .ok_or_else(|| format!("Accuracy: The input \"{}\" is not a number.", payload))?;
        Ok(Accuracy { name: name.to_string(), accuracy })
    }
}

impl Action for Accuracy {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> Kind {
        Kind::Configuration
    }

    fn configure(&self, rule: &mut RuleWithActions) {
        rule.accuracy = self.accuracy;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::block::test_support::{RuleAction, rule};
    use crate::actions::chain::Chain;
    use crate::actions::maturity::Maturity;
    use crate::actions::rev::Rev;
    use crate::actions::ver::Ver;

    /// Configuration actions: accuracy, maturity, rev, ver, chain.
    #[test]
    fn configuration_actions() {
        let a = Accuracy::new("accuracy:'8'").unwrap();
        let m = Maturity::new("maturity:9").unwrap();
        let rev = Rev::new("rev:'2.1.3'");
        let ver = Ver::new("ver:'CRS/3'");
        let c = Chain::new("chain");
        for x in [&a as &dyn Action, &m, &rev, &ver, &c] {
            assert_eq!(x.kind(), Kind::Configuration);
        }
        assert_eq!((a.name(), rev.name(), c.name()), ("accuracy", "rev", "chain"));
        let r = rule(vec![
            RuleAction::Other(Box::new(a)),
            RuleAction::Other(Box::new(m)),
            RuleAction::Other(Box::new(rev)),
            RuleAction::Other(Box::new(ver)),
            RuleAction::Other(Box::new(c)),
        ]);
        assert_eq!(r.accuracy, 8);
        assert_eq!(r.maturity, 9);
        assert_eq!(r.rev, "2.1.3");
        assert_eq!(r.ver, "CRS/3");
        assert!(r.is_chained());

        assert_eq!(Accuracy::new("accuracy:x").unwrap_err(), "Accuracy: The input \"x\" is not a number.");
        assert_eq!(Maturity::new("maturity:").unwrap_err(), "Maturity: The input \"\" is not a number.");
    }
}
