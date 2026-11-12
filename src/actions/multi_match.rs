//! Port of `src/actions/multi_match.cc`, `src/actions/multi_match.h`.
//!
//! `multiMatch` — a marker: `RuleWithActions` records its presence and then
//! runs the operator against every intermediate transformation result.

use crate::actions::action::{Action, name_of};

#[derive(Debug)]
pub struct MultiMatch {
    name: String,
}

impl MultiMatch {
    pub fn new(action: &str) -> Self {
        MultiMatch { name: name_of(action) }
    }
}

impl Action for MultiMatch {
    fn name(&self) -> &str {
        &self.name
    }
}
