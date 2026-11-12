//! Port of `src/actions/ctl/request_body_processor_xml.cc`, `src/actions/ctl/request_body_processor_xml.h`.
//!
//! `ctl:requestBodyProcessor=XML` — parses the request body as XML.

use crate::actions::action::{Action, name_of};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::{RequestBodyType, Transaction};

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

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, _rm: &mut RuleMessage<'_>) {
        t.request_body_processor = RequestBodyType::XMLRequestBody;
        let offset = t.vars.offset;
        t.vars.reqbody_processor.set(b"XML", offset);
    }
}
