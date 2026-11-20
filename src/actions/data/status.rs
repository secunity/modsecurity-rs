//! `status:N` — the HTTP status code used by the disruptive actions.

use crate::actions::action::Action;
use crate::actions::context::ActionContext;

#[derive(Debug)]
pub struct Status {
    name: String,
    status: u16,
}

impl Status {
    pub fn new(name: &str, payload: &str) -> Result<Self, String> {
        let digits = !payload.is_empty() && payload.bytes().all(|c| c.is_ascii_digit());
        let status =
            payload.parse().ok().filter(|_| digits).ok_or_else(|| format!("Not a valid number: {}", payload))?;
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
