//! Port of `src/actions/capture.cc`, `src/actions/capture.h`.
//!
//! `capture` — a marker: `RuleWithActions` records its presence and the
//! operators store their captures in `TX:0..9` when it is set.

use crate::actions::action::{Action, name_of};

#[derive(Debug)]
pub struct Capture {
    name: String,
}

impl Capture {
    pub fn new(action: &str) -> Self {
        Capture { name: name_of(action) }
    }
}

impl Action for Capture {
    fn name(&self) -> &str {
        &self.name
    }
}
