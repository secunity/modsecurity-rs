//! `ctl:requestBodyProcessor=XML` — parses the request body as XML.

use crate::actions::action::Action;
use crate::actions::context::ActionContext;
use crate::transaction::RequestBodyProcessor;

#[derive(Debug)]
pub struct RequestBodyProcessorXML {
    name: String,
}

impl RequestBodyProcessorXML {
    pub fn new(name: &str) -> Self {
        RequestBodyProcessorXML { name: name.to_string() }
    }
}

impl Action for RequestBodyProcessorXML {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, cx: &mut ActionContext<'_, '_, '_>) {
        cx.set_request_body_processor(RequestBodyProcessor::Xml, b"XML");
    }
}
