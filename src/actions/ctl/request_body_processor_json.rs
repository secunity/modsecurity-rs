//! Port of `src/actions/ctl/request_body_processor_json.cc`, `src/actions/ctl/request_body_processor_json.h`.
//!
//! `ctl:requestBodyProcessor=JSON` — parses the request body as JSON.

use crate::actions::action::{Action, name_of};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::{RequestBodyType, Transaction};

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

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, _rm: &mut RuleMessage<'_>) {
        t.request_body_processor = RequestBodyType::JSONRequestBody;
        let offset = t.vars.offset;
        t.vars.reqbody_processor.set(b"JSON", offset);
    }
}
