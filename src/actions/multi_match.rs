//! Port of `src/actions/multi_match.cc`, `src/actions/multi_match.h`.
//!
//! `multiMatch` — a marker: `RuleWithActions` records its presence and then
//! runs the operator against every intermediate transformation result.

use crate::actions::action::{Action, ActionBase};

#[derive(Debug)]
pub struct MultiMatch {
    pub base: ActionBase,
}

impl MultiMatch {
    pub fn new(action: &str) -> Self {
        MultiMatch { base: ActionBase::new(action) }
    }
}

impl Action for MultiMatch {
    crate::action_base_accessors!();
}
