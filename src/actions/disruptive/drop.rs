//! `drop` — meant to close the connection; executes `deny` instead.

use crate::actions::action::{Action, name_of};
use crate::actions::context::ActionContext;

#[derive(Debug)]
pub struct Drop {
    name: String,
}

impl Drop {
    pub fn new(action: &str) -> Self {
        Drop { name: name_of(action) }
    }
}

impl Action for Drop {
    fn name(&self) -> &str {
        &self.name
    }

    fn is_disruptive(&self) -> bool {
        true
    }

    fn evaluate(&self, cx: &mut ActionContext<'_, '_, '_>) {
        crate::ms_dbg!(cx, 8, "Running action drop [executing deny instead of drop.]");
        if cx.intervention_status() == 200 {
            cx.set_intervention_status(403);
        }
        cx.disrupt();
    }
}
