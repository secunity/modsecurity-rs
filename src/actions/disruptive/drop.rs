//! `drop` — meant to close the connection; executes `deny` instead.

use crate::actions::action::Action;
use crate::actions::context::ActionContext;

#[derive(Debug)]
pub struct Drop {
    name: String,
}

impl Drop {
    pub fn new(name: &str) -> Self {
        Drop { name: name.to_string() }
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
        // 403 unless a `status` action set another status. A `status:200`
        // would let the request through: it answers 403 too.
        let status = cx.intervention_status().filter(|&status| status != 200).unwrap_or(403);
        cx.disrupt(status, None);
    }
}
