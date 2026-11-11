//! Port of `src/actions/ver.cc`, `src/actions/ver.h`.
//!
//! `ver:'...'` — the rule set version (configuration time).

use crate::actions::action::{Action, ActionBase, Kind};
use crate::rule_with_actions::RuleWithActions;

#[derive(Debug)]
pub struct Ver {
    pub base: ActionBase,
}

impl Ver {
    pub fn new(action: &str) -> Self {
        Ver { base: ActionBase::with_kind(action, Kind::ConfigurationKind) }
    }
}

impl Action for Ver {
    crate::action_base_accessors!();

    fn configure(&self, rule: &mut RuleWithActions) -> bool {
        rule.ver = self.base.parser_payload.clone();
        true
    }
}
