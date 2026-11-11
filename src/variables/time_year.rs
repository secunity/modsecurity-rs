//! Port of `src/variables/time_year.cc`, `src/variables/time_year.h`.
//!
//! `TIME_YEAR`: the year (`%Y`). The C++ code stored the value in a transaction member
//! (`m_variableTimeYear`) before pointing the result at it; here the value is
//! computed and owned by the result.

use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;
use crate::variable_value::VariableValue;
use crate::variables::variable::{Variable, VariableBase};

/// `TimeYear`
#[derive(Debug)]
pub struct TimeYear {
    pub base: VariableBase,
    pub ret_name: String,
}

impl TimeYear {
    /// `TimeYear(name)`: `name` is the token as written in the rule.
    pub fn new(name: &str) -> Self {
        TimeYear { base: VariableBase::new(name), ret_name: "TIME_YEAR".to_string() }
    }
}

impl Variable for TimeYear {
    fn base(&self) -> &VariableBase {
        &self.base
    }
    fn base_mut(&mut self) -> &mut VariableBase {
        &mut self.base
    }
    fn evaluate(&self, _t: &Transaction<'_>, _rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        let value = crate::utils::system::strftime_local(crate::utils::system::now(), "%Y");
        l.push(VariableValue::new(self.ret_name.as_bytes(), value.as_bytes()));
    }
}
