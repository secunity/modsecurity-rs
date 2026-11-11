//! Port of `src/variables/duration.cc`, `src/variables/duration.h`.
//!
//! `DURATION`: the (CPU) seconds elapsed since the transaction was created.
//! The C++ code stored the value in `m_variableDuration`; here the value is
//! computed and owned by the result.

use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;
use crate::variable_value::VariableValue;
use crate::variables::variable::{Variable, VariableBase};

/// `Duration`
#[derive(Debug)]
pub struct Duration {
    pub base: VariableBase,
    pub ret_name: String,
}

impl Duration {
    /// `Duration(name)`: `name` is the token as written in the rule.
    pub fn new(name: &str) -> Self {
        Duration { base: VariableBase::new(name), ret_name: "DURATION".to_string() }
    }
}

impl Variable for Duration {
    fn base(&self) -> &VariableBase {
        &self.base
    }
    fn base_mut(&mut self) -> &mut VariableBase {
        &mut self.base
    }
    fn evaluate(&self, t: &Transaction<'_>, _rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        let e = crate::utils::system::cpu_seconds() - t.creation_time_stamp;
        // `std::to_string(double)` formats with "%f".
        let value = format!("{:.6}", e);
        l.push(VariableValue::new(self.ret_name.as_bytes(), value.as_bytes()));
    }
}
