//! `ctl:requestBodyAccess=On|Off` — overrides `SecRequestBodyAccess` for
//! the transaction.

use crate::actions::action::Action;
use crate::actions::context::ActionContext;

#[derive(Debug)]
pub struct RequestBodyAccess {
    name: String,
    request_body_access: bool,
}

impl RequestBodyAccess {
    /// `name` is the action name as written; `request_body_access` is
    /// whether the value is `On`.
    pub fn new(name: &str, request_body_access: bool) -> Self {
        RequestBodyAccess { name: name.to_string(), request_body_access }
    }
}

impl Action for RequestBodyAccess {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, cx: &mut ActionContext<'_, '_, '_>) {
        cx.set_request_body_access(self.request_body_access);
    }
}
