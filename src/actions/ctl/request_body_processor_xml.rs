//! `ctl:requestBodyProcessor=XML` — parses the request body as XML.

use crate::actions::action::{Action, name_of};
use crate::actions::context::ActionContext;
use crate::transaction::RequestBodyType;

#[derive(Debug)]
pub struct RequestBodyProcessorXML {
    name: String,
}

impl RequestBodyProcessorXML {
    pub fn new(action: &str) -> Self {
        RequestBodyProcessorXML { name: name_of(action) }
    }
}

impl Action for RequestBodyProcessorXML {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, cx: &mut ActionContext<'_, '_, '_>) {
        cx.set_request_body_processor(RequestBodyType::XMLRequestBody, b"XML");
    }
}
