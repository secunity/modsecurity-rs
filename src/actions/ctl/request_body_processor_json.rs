//! `ctl:requestBodyProcessor=JSON` — parses the request body as JSON.

use crate::actions::action::Action;
use crate::actions::context::ActionContext;
use crate::transaction::RequestBodyProcessor;

#[derive(Debug)]
pub struct RequestBodyProcessorJSON {
    name: String,
}

impl RequestBodyProcessorJSON {
    pub fn new(name: &str) -> Self {
        RequestBodyProcessorJSON { name: name.to_string() }
    }
}

impl Action for RequestBodyProcessorJSON {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, cx: &mut ActionContext<'_, '_, '_>) {
        cx.set_request_body_processor(RequestBodyProcessor::Json, b"JSON");
    }
}
