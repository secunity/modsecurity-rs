//! `maturity:N` — the maturity level of the rule (configuration time).

use crate::actions::action::{Action, Kind, name_and_payload};
use crate::rule::Rule;
use crate::utils::string::stoi;

#[derive(Debug)]
pub struct Maturity {
    name: String,
    maturity: i32,
}

impl Maturity {
    pub fn new(action: &str) -> Result<Self, String> {
        let (name, payload) = name_and_payload(action);
        // `std::stoi`: no digits or out of `int` range -> error.
        let maturity =
            stoi(payload.as_bytes()).ok_or_else(|| format!("Maturity: The input \"{}\" is not a number.", payload))?;
        Ok(Maturity { name: name.to_string(), maturity })
    }
}

impl Action for Maturity {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> Kind {
        Kind::Configuration
    }

    fn configure(&self, rule: &mut Rule) {
        rule.maturity = self.maturity;
    }
}
