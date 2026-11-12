//! Port of `src/actions/ver.cc`, `src/actions/ver.h`.
//!
//! `ver:'...'` — the rule set version (configuration time).

use crate::actions::action::{Action, Kind, name_and_payload};
use crate::rule_with_actions::RuleWithActions;

#[derive(Debug)]
pub struct Ver {
    name: String,
    ver: String,
}

impl Ver {
    pub fn new(action: &str) -> Self {
        let (name, ver) = name_and_payload(action);
        Ver { name: name.to_string(), ver: ver.to_string() }
    }
}

impl Action for Ver {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> Kind {
        Kind::Configuration
    }

    fn configure(&self, rule: &mut RuleWithActions) {
        rule.ver.clone_from(&self.ver);
    }
}
