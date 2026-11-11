//! Port of `src/actions/capture.cc`, `src/actions/capture.h`.
//!
//! `capture` — a marker: `RuleWithActions` records its presence and the
//! operators store their captures in `TX:0..9` when it is set.

use crate::actions::action::{Action, ActionBase};

#[derive(Debug)]
pub struct Capture {
    pub base: ActionBase,
}

impl Capture {
    pub fn new(action: &str) -> Self {
        Capture { base: ActionBase::new(action) }
    }
}

impl Action for Capture {
    crate::action_base_accessors!();
}
