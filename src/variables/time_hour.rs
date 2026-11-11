//! Port of `src/variables/time_hour.cc`, `src/variables/time_hour.h`.
//!
//! `TIME_HOUR`: the hour (`%H`). The C++ code stored the value in a transaction member
//! (`m_variableTimeHour`) before pointing the result at it; here the value is
//! computed and owned by the result.

use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;
use crate::variable_value::VariableValue;
use crate::variables::variable::{Variable, VariableBase};

/// `TimeHour`
#[derive(Debug)]
pub struct TimeHour {
    pub base: VariableBase,
    pub ret_name: String,
}

impl TimeHour {
    /// `TimeHour(name)`: `name` is the token as written in the rule.
    pub fn new(name: &str) -> Self {
        TimeHour { base: VariableBase::new(name), ret_name: "TIME_HOUR".to_string() }
    }
}

impl Variable for TimeHour {
    fn base(&self) -> &VariableBase {
        &self.base
    }
    fn base_mut(&mut self) -> &mut VariableBase {
        &mut self.base
    }
    fn evaluate(&self, _t: &Transaction<'_>, _rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        let value = crate::utils::system::strftime_local(crate::utils::system::now(), "%H");
        l.push(VariableValue::new(self.ret_name.as_bytes(), value.as_bytes()));
    }
}
