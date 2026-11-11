//! Port of `src/variables/highest_severity.cc`,
//! `src/variables/highest_severity.h`.
//!
//! `HIGHEST_SEVERITY`: the highest severity (lowest number) of the rules
//! matched so far, 255 if none. The C++ code stored the text in
//! `m_variableHighestSeverityAction`; here it is computed.

use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;
use crate::variable_value::VariableValue;
use crate::variables::variable::{Variable, VariableBase};

/// `HighestSeverity`
#[derive(Debug)]
pub struct HighestSeverity {
    pub base: VariableBase,
}

impl HighestSeverity {
    /// `HighestSeverity(name)`: `name` is the token as written in the rule.
    pub fn new(name: &str) -> Self {
        HighestSeverity { base: VariableBase::new(name) }
    }
}

impl Variable for HighestSeverity {
    fn base(&self) -> &VariableBase {
        &self.base
    }
    fn base_mut(&mut self) -> &mut VariableBase {
        &mut self.base
    }
    fn evaluate(&self, t: &Transaction<'_>, _rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        let value = t.highest_severity_action.to_string();
        l.push(VariableValue::new(self.base.full_name.as_bytes(), value.as_bytes()));
    }
}
