//! Rule evaluation: running the rules of a rule set against a
//! transaction. The rules (`crate::rule`, `crate::rules_set`) are what a
//! configuration says, built when it is loaded; this module runs them and
//! keeps where the run is in the transaction ([`EvalState`]).

mod actions;
mod phase;
mod rule;
mod sec_rule;

use crate::actions::disruptive::allow::AllowType;
use crate::rule::{Rule, TransformationResults};
use crate::variables::variable::Variable;
use crate::variables::variable_value::VariableValue;

pub(crate) use phase::run as run_phase;

/// Where rule evaluation is: skips, markers, `allow`, the chain being
/// evaluated, captures, and buffers reused from rule to rule.
#[derive(Default)]
pub(crate) struct EvalState<'a> {
    /// Rules still to be skipped because of a `skip` action.
    pub(crate) skip_next: usize,
    /// The `SecMarker` being skipped to (by `skipAfter`).
    pub(crate) marker: Option<String>,
    /// Set by a matching `allow` action, until the rules it covers are
    /// skipped.
    pub(crate) allow_type: Option<AllowType>,
    /// Chain ancestors of the rule being evaluated, innermost last (a
    /// rule has no pointer to its parent).
    pub(crate) chained_rule_parents: Vec<&'a Rule>,
    /// Matched strings, used by the `capture` action.
    pub(crate) matched: Vec<Vec<u8>>,
    /// Buffers reused by rule evaluation.
    pub(crate) scratch: EvalScratch<'a>,
}

/// Buffers of `SecRule::evaluate`, kept in the transaction so
/// that evaluating a rule does not allocate them again.
#[derive(Default)]
pub struct EvalScratch<'a> {
    /// The rule's final list of variables.
    pub vars: Vec<&'a Variable>,
    /// The values of one variable.
    pub e: Vec<VariableValue>,
    /// The transformation results of one value.
    pub values: TransformationResults,
}
