//! `multiMatch` — a marker: `Rule` records its presence and then
//! runs the operator against every intermediate transformation result.

use crate::actions::action::Action;

#[derive(Debug)]
pub struct MultiMatch {
    name: String,
}

impl MultiMatch {
    pub fn new(name: &str) -> Self {
        MultiMatch { name: name.to_string() }
    }
}

impl Action for MultiMatch {
    fn name(&self) -> &str {
        &self.name
    }
}
