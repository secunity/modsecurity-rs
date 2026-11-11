//! Port of `src/variables/time_wday.cc`, `src/variables/time_wday.h`.
//!
//! `TIME_WDAY`: the day of the week, 1 (Monday) to 7 (`%u`). The C++ code stored the value in a transaction member
//! (`m_variableTimeWDay`) before pointing the result at it; here the value is
//! computed and owned by the result.

use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;
use crate::variable_value::VariableValue;
use crate::variables::variable::{Variable, VariableBase};

/// `TimeWDay`
#[derive(Debug)]
pub struct TimeWDay {
    pub base: VariableBase,
    pub ret_name: String,
}

impl TimeWDay {
    /// `TimeWDay(name)`: `name` is the token as written in the rule.
    pub fn new(name: &str) -> Self {
        TimeWDay { base: VariableBase::new(name), ret_name: "TIME_WDAY".to_string() }
    }
}

impl Variable for TimeWDay {
    fn base(&self) -> &VariableBase {
        &self.base
    }
    fn base_mut(&mut self) -> &mut VariableBase {
        &mut self.base
    }
    fn evaluate(&self, _t: &Transaction<'_>, _rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        let value = crate::utils::system::strftime_local(crate::utils::system::now(), "%u");
        l.push(VariableValue::new(self.ret_name.as_bytes(), value.as_bytes()));
    }
}
