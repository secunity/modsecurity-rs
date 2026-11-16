//! `chain` — chains the rule with the one that follows (configuration
//! time).

use crate::actions::action::{Action, Kind, name_of};
use crate::rule::Rule;

#[derive(Debug)]
pub struct Chain {
    name: String,
}

impl Chain {
    pub fn new(action: &str) -> Self {
        Chain { name: name_of(action) }
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
