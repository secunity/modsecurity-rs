//! `skipAfter:MARKER` — skips the rules up to (and including) the
//! `SecMarker` of that name.

use crate::actions::action::Action;
use crate::actions::context::ActionContext;

#[derive(Debug)]
pub struct SkipAfter {
    name: String,
    skip_name: String,
}

impl SkipAfter {
    pub fn new(name: &str, skip_name: &str) -> Self {
        SkipAfter { name: name.to_string(), skip_name: skip_name.to_string() }
    }
}

impl Action for SkipAfter {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, cx: &mut ActionContext<'_, '_, '_>) {
        crate::ms_dbg!(cx, 5, "Setting skipAfter for: {}", self.skip_name);
        cx.skip_after(&self.skip_name);
    }
}
