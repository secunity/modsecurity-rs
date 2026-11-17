//! `capture` — a marker: `Rule` records its presence and the
//! operators store their captures in `TX:0..9` when it is set.

use crate::actions::action::Action;

#[derive(Debug)]
pub struct Capture {
    name: String,
}

impl Capture {
    pub fn new(name: &str) -> Self {
        Capture { name: name.to_string() }
    }
}

impl Action for Capture {
    fn name(&self) -> &str {
        &self.name
    }
}
