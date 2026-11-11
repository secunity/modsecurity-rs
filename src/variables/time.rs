//! Port of `src/variables/time.cc`, `src/variables/time.h`.
//!
//! `TIME`: the local time as `hh:mm:ss`. The C++ code stored the value in a transaction member
//! (`m_variableTime`) before pointing the result at it; here the value is
//! computed and owned by the result.

use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;
use crate::variable_value::VariableValue;
use crate::variables::variable::{Variable, VariableBase};

/// `Time`
#[derive(Debug)]
pub struct Time {
    pub base: VariableBase,
    pub ret_name: String,
}

impl Time {
    /// `Time(name)`: `name` is the token as written in the rule.
    pub fn new(name: &str) -> Self {
        Time { base: VariableBase::new(name), ret_name: "TIME".to_string() }
    }
}

impl Variable for Time {
    fn base(&self) -> &VariableBase {
        &self.base
    }
    fn base_mut(&mut self) -> &mut VariableBase {
        &mut self.base
    }
    fn evaluate(&self, _t: &Transaction<'_>, _rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        let value = crate::utils::system::strftime_local(crate::utils::system::now(), "%H:%M:%S");
        l.push(VariableValue::new(self.ret_name.as_bytes(), value.as_bytes()));
    }
}
