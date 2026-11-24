//! What only a `SecRule` has: its targets and its operator (evaluated by
//! `crate::eval`).

use crate::operators::operator::RuleOperator;
use crate::variables::variable::Variable;

/// The `SecRule` specific part of a rule: its targets and its operator.
#[derive(Debug)]
pub struct SecRule {
    pub variables: Vec<Variable>,
    pub operator: RuleOperator,
}

impl SecRule {
    pub fn new(op: RuleOperator, mut variables: Vec<Variable>) -> Self {
        // The list is final: give back what the parser over-allocated.
        variables.shrink_to_fit();
        SecRule { variables, operator: op }
    }

    /// The operator name (`rx`, `pm`, ...).
    pub fn operator_name(&self) -> &str {
        self.operator.op.name()
    }
}
