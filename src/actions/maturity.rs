//! Port of `src/actions/maturity.cc`, `src/actions/maturity.h`.
//!
//! `maturity:N` — the maturity level of the rule (configuration time).

use crate::actions::action::{Action, ActionBase, Kind};
use crate::rule_with_actions::RuleWithActions;
use crate::utils::string::stoi;

#[derive(Debug)]
pub struct Maturity {
    pub base: ActionBase,
    maturity: i32,
}

impl Maturity {
    pub fn new(action: &str) -> Self {
        Maturity { base: ActionBase::with_kind(action, Kind::ConfigurationKind), maturity: 0 }
    }
}

impl Action for Maturity {
    crate::action_base_accessors!();

    fn init(&mut self) -> Result<(), String> {
        // `std::stoi`: no digits or out of `int` range -> error.
        match stoi(self.base.parser_payload.as_bytes()).and_then(|v| i32::try_from(v).ok()) {
            Some(a) => {
                self.maturity = a;
                Ok(())
            }
            None => Err(format!("Maturity: The input \"{}\" is not a number.", self.base.parser_payload)),
        }
    }

    fn configure(&self, rule: &mut RuleWithActions) -> bool {
        rule.maturity = self.maturity;
        true
    }
}
