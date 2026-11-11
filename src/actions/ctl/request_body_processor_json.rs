//! Port of `src/actions/ctl/request_body_processor_json.cc`, `src/actions/ctl/request_body_processor_json.h`.
//!
//! `ctl:requestBodyProcessor=JSON` — parses the request body as JSON.

use crate::actions::action::{Action, ActionBase};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::{RequestBodyType, Transaction};

#[derive(Debug)]
pub struct RequestBodyProcessorJSON {
    pub base: ActionBase,
}

impl RequestBodyProcessorJSON {
    pub fn new(action: &str) -> Self {
        RequestBodyProcessorJSON { base: ActionBase::new(action) }
    }
}

impl Action for RequestBodyProcessorJSON {
    crate::action_base_accessors!();

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, _rm: &mut RuleMessage<'_>) -> bool {
        t.request_body_processor = RequestBodyType::JSONRequestBody;
        let offset = t.vars.offset;
        t.vars.reqbody_processor.set(b"JSON", offset);
        true
    }
}
