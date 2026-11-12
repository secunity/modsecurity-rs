//! Port of `src/actions/rev.cc`, `src/actions/rev.h`.
//!
//! `rev:'1.2'` — the rule revision (configuration time).

use crate::actions::action::{Action, Kind, name_and_payload};
use crate::rule_with_actions::RuleWithActions;

#[derive(Debug)]
pub struct Rev {
    name: String,
    rev: String,
}

impl Rev {
    pub fn new(action: &str) -> Self {
        let (name, rev) = name_and_payload(action);
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

    fn configure(&self, rule: &mut RuleWithActions) {
        rule.rev.clone_from(&self.rev);
    }
}
