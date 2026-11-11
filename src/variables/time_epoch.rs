//! Port of `src/variables/time_epoch.cc`, `src/variables/time_epoch.h`.
//!
//! `TIME_EPOCH`: the seconds since the epoch. The C++ code stored the value in a transaction member
//! (`m_variableTimeEpoch`) before pointing the result at it; here the value is
//! computed and owned by the result.

use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;
use crate::variable_value::VariableValue;
use crate::variables::variable::{Variable, VariableBase};

/// `TimeEpoch`
#[derive(Debug)]
pub struct TimeEpoch {
    pub base: VariableBase,
    pub ret_name: String,
}

impl TimeEpoch {
    /// `TimeEpoch(name)`: `name` is the token as written in the rule.
    pub fn new(name: &str) -> Self {
        TimeEpoch { base: VariableBase::new(name), ret_name: "TIME_EPOCH".to_string() }
    }
}

impl Variable for TimeEpoch {
    fn base(&self) -> &VariableBase {
        &self.base
    }
    fn base_mut(&mut self) -> &mut VariableBase {
        &mut self.base
    }
    fn evaluate(&self, _t: &Transaction<'_>, _rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        let value = crate::utils::system::now().to_string();
        l.push(VariableValue::new(self.ret_name.as_bytes(), value.as_bytes()));
    }
}
