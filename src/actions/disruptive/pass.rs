//! `pass` — continues with the next rule; discards any pending
//! intervention.

use crate::actions::action::{Action, name_of};
use crate::actions::context::ActionContext;

#[derive(Debug)]
pub struct Pass {
    name: String,
}

impl Pass {
    pub fn new(action: &str) -> Self {
        Pass { name: name_of(action) }
    }
}

impl Action for Pass {
    fn name(&self) -> &str {
        &self.name
    }

    fn is_disruptive(&self) -> bool {
        true
    }

    fn evaluate(&self, cx: &mut ActionContext<'_, '_, '_>) {
        // intervention::free + reset: drops the url and log too.
        cx.reset_intervention();
        crate::ms_dbg!(cx, 8, "Running action pass");
    }
}
