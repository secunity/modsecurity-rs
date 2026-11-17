//! `nolog` — the rule match is not to be logged.

use crate::actions::action::Action;
use crate::actions::context::ActionContext;

#[derive(Debug)]
pub struct NoLog {
    name: String,
}

impl NoLog {
    pub fn new(name: &str) -> Self {
        NoLog { name: name.to_string() }
    }
}

impl Action for NoLog {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, cx: &mut ActionContext<'_, '_, '_>) {
        cx.set_save_message(false);
    }
}
