//! `ctl:requestBodyAccess=On|Off` — overrides `SecRequestBodyAccess` for
//! the transaction.

use crate::actions::action::{Action, name_of};
use crate::actions::context::ActionContext;

#[derive(Debug)]
pub struct RequestBodyAccess {
    name: String,
    request_body_access: bool,
}

impl RequestBodyAccess {
    /// `action` is the `ctl:requestBodyAccess=` text of the rule.
    pub fn new(action: &str, request_body_access: bool) -> Self {
        RequestBodyAccess { name: name_of(action), request_body_access }
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
