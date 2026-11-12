//! Port of `src/actions/ctl/request_body_access.cc`, `src/actions/ctl/request_body_access.h`.
//!
//! `ctl:requestBodyAccess=On|Off` — overrides `SecRequestBodyAccess` for
//! the transaction.

use crate::actions::action::{Action, name_of};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct RequestBodyAccess {
    name: String,
    request_body_access: bool,
}

impl RequestBodyAccess {
    /// `action` is the `ctl:requestBodyAccess=` text of the rule.
    pub fn new(action: &str, request_body_access: bool) -> Self {
        RequestBodyAccess { name: name_of(action), request_body_access }
    }
}

impl Action for RequestBodyAccess {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, _rm: &mut RuleMessage<'_>) {
        t.request_body_access = Some(self.request_body_access);
    }
}
