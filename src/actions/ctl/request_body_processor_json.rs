//! `ctl:requestBodyProcessor=JSON` — parses the request body as JSON.

use crate::actions::action::{Action, name_of};
use crate::actions::context::ActionContext;
use crate::transaction::RequestBodyType;

#[derive(Debug)]
pub struct RequestBodyProcessorJSON {
    name: String,
}

impl RequestBodyProcessorJSON {
    pub fn new(action: &str) -> Self {
        RequestBodyProcessorJSON { name: name_of(action) }
    }
}

impl Action for RequestBodyProcessorJSON {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, cx: &mut ActionContext<'_, '_, '_>) {
        cx.set_request_body_processor(RequestBodyType::JSONRequestBody, b"JSON");
    }
}
