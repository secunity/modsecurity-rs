//! Port of `src/variables/time_mon.cc`, `src/variables/time_mon.h`.
//!
//! `TIME_MON`: the month, 1 to 12, not zero padded. The C++ code stored the value in a transaction member
//! (`m_variableTimeMon`) before pointing the result at it; here the value is
//! computed and owned by the result.

use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;
use crate::variable_value::VariableValue;
use crate::variables::variable::{Variable, VariableBase};

/// `TimeMon`
#[derive(Debug)]
pub struct TimeMon {
    pub base: VariableBase,
    pub ret_name: String,
}

impl TimeMon {
    /// `TimeMon(name)`: `name` is the token as written in the rule.
    pub fn new(name: &str) -> Self {
        TimeMon { base: VariableBase::new(name), ret_name: "TIME_MON".to_string() }
    }
}

impl Variable for TimeMon {
    fn base(&self) -> &VariableBase {
        &self.base
    }
    fn base_mut(&mut self) -> &mut VariableBase {
        &mut self.base
    }
    fn evaluate(&self, _t: &Transaction<'_>, _rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        let timeinfo = crate::utils::system::localtime(crate::utils::system::now());
        // `tm_mon + 1` in C++: jiff months are already 1 to 12.
        let value = timeinfo.month().to_string();
        l.push(VariableValue::new(self.ret_name.as_bytes(), value.as_bytes()));
    }
}
