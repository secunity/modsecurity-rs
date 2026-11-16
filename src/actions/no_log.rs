//! `nolog` — the rule match is not to be logged.

use crate::actions::action::{Action, name_of};
use crate::actions::context::ActionContext;

#[derive(Debug)]
pub struct NoLog {
    name: String,
}

impl NoLog {
    pub fn new(action: &str) -> Self {
        NoLog { name: name_of(action) }
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
