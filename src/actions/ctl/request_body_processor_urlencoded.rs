//! Port of `src/actions/ctl/request_body_processor_urlencoded.cc`, `src/actions/ctl/request_body_processor_urlencoded.h`.
//!
//! `ctl:requestBodyProcessor=URLENCODED` — parses the request body as
//! `application/x-www-form-urlencoded`. (Unlike the JSON and XML variants
//! C++ sets the request body *type* here, not the processor; kept.)

use crate::actions::action::{Action, ActionBase};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::{RequestBodyType, Transaction};

#[derive(Debug)]
pub struct RequestBodyProcessorURLENCODED {
    pub base: ActionBase,
}

impl RequestBodyProcessorURLENCODED {
    pub fn new(action: &str) -> Self {
        RequestBodyProcessorURLENCODED { base: ActionBase::new(action) }
    }
}

impl Action for RequestBodyProcessorURLENCODED {
    crate::action_base_accessors!();

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, _rm: &mut RuleMessage<'_>) {
        t.request_body_type = RequestBodyType::WWWFormUrlEncoded;
        let offset = t.vars.offset;
        t.vars.reqbody_processor.set(b"URLENCODED", offset);
    }
}
