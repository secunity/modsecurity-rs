//! Port of `src/actions/ctl/request_body_access.cc`, `src/actions/ctl/request_body_access.h`.
//!
//! `ctl:requestBodyAccess=On|Off` — overrides `SecRequestBodyAccess` for
//! the transaction.

use crate::actions::action::{Action, ActionBase};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::rules_set_properties::ConfigBoolean;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct RequestBodyAccess {
    pub base: ActionBase,
    pub request_body_access: bool,
}

impl RequestBodyAccess {
    pub fn new(action: &str) -> Self {
        RequestBodyAccess { base: ActionBase::new(action), request_body_access: false }
    }
}

impl Action for RequestBodyAccess {
    crate::action_base_accessors!();

    fn init(&mut self) -> Result<(), String> {
        // The parser builds the payload as `requestBodyAccess=<true|false>`.
        let what = self.base.parser_payload.get(18..).unwrap_or("");
        self.request_body_access = match what {
            "true" => true,
            "false" => false,
            _ => {
                return Err(format!("Internal error. Expected: true or false, got: {}", self.base.parser_payload));
            }
        };
        Ok(())
    }

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, _rm: &mut RuleMessage<'_>) -> bool {
        t.request_body_access =
            if self.request_body_access { ConfigBoolean::TrueConfigBoolean } else { ConfigBoolean::FalseConfigBoolean };
        true
    }
}
