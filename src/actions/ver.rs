//! `ver:'...'` — the rule set version (configuration time).

use crate::actions::action::{Action, Kind};
use crate::rule::Rule;

#[derive(Debug)]
pub struct Ver {
    name: String,
    ver: String,
}

impl Ver {
    pub fn new(name: &str, ver: &str) -> Self {
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

    fn configure(&self, rule: &mut Rule) {
        rule.metadata.ver.clone_from(&self.ver);
    }
}
