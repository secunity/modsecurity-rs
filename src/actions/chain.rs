//! Port of `src/actions/chain.cc`, `src/actions/chain.h`.
//!
//! `chain` — chains the rule with the one that follows (configuration
//! time).

use crate::actions::action::{Action, ActionBase, Kind};
use crate::rule_with_actions::RuleWithActions;

#[derive(Debug)]
pub struct Chain {
    pub base: ActionBase,
}

impl Chain {
    pub fn new(action: &str) -> Self {
        Chain { base: ActionBase::with_kind(action, Kind::ConfigurationKind) }
    }
}

impl Action for Chain {
    crate::action_base_accessors!();

    fn configure(&self, rule: &mut RuleWithActions) -> bool {
        rule.set_chained(true);
        true
    }
}
