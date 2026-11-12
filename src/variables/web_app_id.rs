//! Port of `src/variables/web_app_id.h`.
//!
//! `WEBAPPID`: the `SecWebAppId` of the rule set.

use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;
use crate::variable_value::VariableValue;
use crate::variables::variable::{Variable, VariableBase};

/// `WebAppId`
#[derive(Debug)]
pub struct WebAppId {
    pub base: VariableBase,
}

impl WebAppId {
    pub fn new() -> Self {
        WebAppId { base: VariableBase::new("WEBAPPID") }
    }
}

impl Default for WebAppId {
    fn default() -> Self {
        Self::new()
    }
}

impl Variable for WebAppId {
    fn base(&self) -> &VariableBase {
        &self.base
    }
    fn base_mut(&mut self) -> &mut VariableBase {
        &mut self.base
    }
    fn evaluate(&self, t: &Transaction<'_>, _rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        // Note: the C++ code names the value with `m_name`, which is empty
        // for `WEBAPPID` (there is no `:` in the name); kept as is.
        let rname = t.rules.properties.web_app_id();
        l.push(VariableValue::new(self.base.name.as_bytes(), rname));
    }
}
