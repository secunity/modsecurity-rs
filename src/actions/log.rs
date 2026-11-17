//! `log` — the rule match is to be logged.

use crate::actions::action::Action;
use crate::actions::context::ActionContext;

#[derive(Debug)]
pub struct Log {
    name: String,
}

impl Log {
    pub fn new(name: &str) -> Self {
        Log { name: name.to_string() }
    }
}

impl Action for Log {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, cx: &mut ActionContext<'_, '_, '_>) {
        crate::ms_dbg!(cx, 9, "Saving transaction to logs");
        cx.set_save_message(true);
    }
}
