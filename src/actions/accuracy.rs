//! Port of `src/actions/accuracy.cc`, `src/actions/accuracy.h`.
//!
//! `accuracy:N` — the accuracy level of the rule (configuration time).

use crate::actions::action::{Action, ActionBase, Kind};
use crate::rule_with_actions::RuleWithActions;
use crate::utils::string::stoi;

#[derive(Debug)]
pub struct Accuracy {
    pub base: ActionBase,
    accuracy: i32,
}

impl Accuracy {
    pub fn new(action: &str) -> Self {
        Accuracy { base: ActionBase::with_kind(action, Kind::ConfigurationKind), accuracy: 0 }
    }
}

impl Action for Accuracy {
    crate::action_base_accessors!();

    fn init(&mut self) -> Result<(), String> {
        // `std::stoi`: no digits or out of `int` range -> error.
        match stoi(self.base.parser_payload.as_bytes()).and_then(|v| i32::try_from(v).ok()) {
            Some(a) => {
                self.accuracy = a;
                Ok(())
            }
            None => Err(format!("Accuracy: The input \"{}\" is not a number.", self.base.parser_payload)),
        }
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
        let mut a = Accuracy::new("accuracy:'8'");
        let mut m = Maturity::new("maturity:9");
        let mut rev = Rev::new("rev:'2.1.3'");
        let mut ver = Ver::new("ver:'CRS/3'");
        let mut c = Chain::new("chain");
        for x in [&mut a as &mut dyn Action, &mut m, &mut rev, &mut ver, &mut c] {
            assert_eq!(x.action_kind(), Kind::ConfigurationKind);
            x.init().unwrap();
        }
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

        assert_eq!(Accuracy::new("accuracy:x").init(), Err("Accuracy: The input \"x\" is not a number.".to_string()));
        assert_eq!(Maturity::new("maturity:").init(), Err("Maturity: The input \"\" is not a number.".to_string()));
    }
}
