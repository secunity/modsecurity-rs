//! Port of `src/variables/time_sec.cc`, `src/variables/time_sec.h`.
//!
//! `TIME_SEC`: the second (`%S`). The C++ code stored the value in a transaction member
//! (`m_variableTimeSec`) before pointing the result at it; here the value is
//! computed and owned by the result.

use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;
use crate::variable_value::VariableValue;
use crate::variables::variable::{Variable, VariableBase};

/// `TimeSec`
#[derive(Debug)]
pub struct TimeSec {
    pub base: VariableBase,
    pub ret_name: String,
}

impl TimeSec {
    /// `TimeSec(name)`: `name` is the token as written in the rule.
    pub fn new(name: &str) -> Self {
        TimeSec { base: VariableBase::new(name), ret_name: "TIME_SEC".to_string() }
    }
}

impl Variable for TimeSec {
    fn base(&self) -> &VariableBase {
        &self.base
    }
    fn base_mut(&mut self) -> &mut VariableBase {
        &mut self.base
    }
    fn evaluate(&self, _t: &Transaction<'_>, _rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        let value = crate::utils::system::strftime_local(crate::utils::system::now(), "%S");
        l.push(VariableValue::new(self.ret_name.as_bytes(), value.as_bytes()));
    }
}
