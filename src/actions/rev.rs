//! `rev:'1.2'` — the rule revision (configuration time).

use crate::actions::action::{Action, Kind};
use crate::rule::Rule;

#[derive(Debug)]
pub struct Rev {
    name: String,
    rev: String,
}

impl Rev {
    pub fn new(name: &str, rev: &str) -> Self {
        Rev { name: name.to_string(), rev: rev.to_string() }
    }
}

impl Action for Rev {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> Kind {
        Kind::Configuration
    }

    fn configure(&self, rule: &mut Rule) {
        rule.rev.clone_from(&self.rev);
    }
}
