//! Port of `src/actions/ctl/request_body_processor_urlencoded.cc`, `src/actions/ctl/request_body_processor_urlencoded.h`.
//!
//! `ctl:requestBodyProcessor=URLENCODED` — parses the request body as
//! `application/x-www-form-urlencoded`. (Unlike the JSON and XML variants
//! C++ sets the request body *type* here, not the processor; kept.)

use crate::actions::action::{Action, name_of};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::{RequestBodyType, Transaction};

#[derive(Debug)]
pub struct RequestBodyProcessorURLENCODED {
    name: String,
}

impl RequestBodyProcessorURLENCODED {
    pub fn new(action: &str) -> Self {
        RequestBodyProcessorURLENCODED { name: name_of(action) }
    }
}

impl Action for RequestBodyProcessorURLENCODED {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, _rm: &mut RuleMessage<'_>) {
        t.request_body_type = RequestBodyType::WWWFormUrlEncoded;
        let offset = t.vars.offset;
        t.vars.reqbody_processor.set(b"URLENCODED", offset);
    }
}
