//! Port of `src/actions/ctl/request_body_processor_xml.cc`, `src/actions/ctl/request_body_processor_xml.h`.
//!
//! `ctl:requestBodyProcessor=XML` — parses the request body as XML.

use crate::actions::action::{Action, ActionBase};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::{RequestBodyType, Transaction};

#[derive(Debug)]
pub struct RequestBodyProcessorXML {
    pub base: ActionBase,
}

impl RequestBodyProcessorXML {
    pub fn new(action: &str) -> Self {
        RequestBodyProcessorXML { base: ActionBase::new(action) }
    }
}

impl Action for RequestBodyProcessorXML {
    crate::action_base_accessors!();

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, _rm: &mut RuleMessage<'_>) {
        t.request_body_processor = RequestBodyType::XMLRequestBody;
        let offset = t.vars.offset;
        t.vars.reqbody_processor.set(b"XML", offset);
    }
}
