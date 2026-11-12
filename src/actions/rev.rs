//! Port of `src/actions/rev.cc`, `src/actions/rev.h`.
//!
//! `rev:'1.2'` — the rule revision (configuration time).

use crate::actions::action::{Action, ActionBase, Kind};
use crate::rule_with_actions::RuleWithActions;

#[derive(Debug)]
pub struct Rev {
    pub base: ActionBase,
    rev: String,
}

impl Rev {
    pub fn new(action: &str) -> Self {
        Rev { base: ActionBase::with_kind(action, Kind::ConfigurationKind), rev: String::new() }
    }
}

impl Action for Rev {
    crate::action_base_accessors!();

    fn init(&mut self) -> Result<(), String> {
        self.rev = self.base.parser_payload.clone();
        Ok(())
    }

    fn configure(&self, rule: &mut RuleWithActions) {
        rule.rev = self.rev.clone();
    }
}
