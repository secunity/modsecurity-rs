//! `ctl:requestBodyProcessor=URLENCODED` — parses the request body as
//! `application/x-www-form-urlencoded`. (Unlike the JSON and XML variants
//! C++ sets the request body *type* here, not the processor; kept.)

use crate::actions::action::Action;
use crate::actions::context::ActionContext;
use crate::transaction::RequestBodyType;

#[derive(Debug)]
pub struct RequestBodyProcessorURLENCODED {
    name: String,
}

impl RequestBodyProcessorURLENCODED {
    pub fn new(name: &str) -> Self {
        RequestBodyProcessorURLENCODED { name: name.to_string() }
    }
}

impl Action for RequestBodyProcessorURLENCODED {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, cx: &mut ActionContext<'_, '_, '_>) {
        cx.set_request_body_type(RequestBodyType::WWWFormUrlEncoded, b"URLENCODED");
    }
}
