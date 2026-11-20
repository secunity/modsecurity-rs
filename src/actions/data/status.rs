//! `status:N` — the HTTP status code used by the disruptive actions.

use crate::actions::action::Action;
use crate::actions::context::ActionContext;
use crate::utils::string::stoi;

#[derive(Debug)]
pub struct Status {
    name: String,
    status: i32,
}

impl Status {
    pub fn new(name: &str, payload: &str) -> Result<Self, String> {
        // No digits, or a value out of the `int` range, is an error.
        let status = stoi(payload.as_bytes()).ok_or_else(|| format!("Not a valid number: {}", payload))?;
        Ok(Status { name: name.to_string(), status })
    }
}

impl Action for Status {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, cx: &mut ActionContext<'_, '_, '_>) {
        cx.set_intervention_status(self.status);
    }
}
