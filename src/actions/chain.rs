//! `chain` — chains the rule with the one that follows (configuration
//! time).

use crate::actions::action::{Action, Kind};
use crate::rule::Rule;

#[derive(Debug)]
pub struct Chain {
    name: String,
}

impl Chain {
    pub fn new(name: &str) -> Self {
        Chain { name: name.to_string() }
    }
}

impl Action for Chain {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> Kind {
        Kind::Configuration
    }

    fn configure(&self, rule: &mut Rule) {
        rule.set_chained(true);
    }
}
