//! Port of `headers/modsecurity/rule.h` and `src/rule.cc`.
//!
//! The abstract C++ `Rule` base has two direct subclasses, `RuleMarker`
//! (`SecMarker`) and `RuleWithActions` (everything else); `Rule` is the
//! closed enum over them.

use crate::rule_marker::RuleMarker;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;

// Rules always live behind an `Arc`, so the size difference between the
// variants does not matter.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum Rule {
    Marker(RuleMarker),
    WithActions(RuleWithActions),
}

impl Rule {
    /// `evaluate(transaction)`
    pub fn evaluate<'a>(&'a self, t: &mut Transaction<'a>) -> bool {
        match self {
            Rule::Marker(m) => m.evaluate(t),
            Rule::WithActions(r) => r.evaluate(t),
        }
    }

    pub fn file_name(&self) -> &str {
        match self {
            Rule::Marker(m) => &m.file_name,
            Rule::WithActions(r) => &r.file_name,
        }
    }

    pub fn line_number(&self) -> i32 {
        match self {
            Rule::Marker(m) => m.line_number,
            Rule::WithActions(r) => r.line_number,
        }
    }

    pub fn get_phase(&self) -> i32 {
        match self {
            Rule::Marker(m) => m.phase,
            Rule::WithActions(r) => r.get_phase(),
        }
    }

    pub fn set_phase(&mut self, phase: i32) {
        match self {
            Rule::Marker(m) => m.phase = phase,
            Rule::WithActions(r) => r.set_phase(phase),
        }
    }

    /// `getReference`
    pub fn get_reference(&self) -> String {
        match self {
            Rule::Marker(m) => format!("{}:{}", m.file_name, m.line_number),
            Rule::WithActions(r) => r.get_reference(),
        }
    }

    pub fn is_marker(&self) -> bool {
        matches!(self, Rule::Marker(_))
    }

    /// `dynamic_cast<RuleWithActions *>`
    pub fn as_rule_with_actions(&self) -> Option<&RuleWithActions> {
        match self {
            Rule::WithActions(r) => Some(r),
            Rule::Marker(_) => None,
        }
    }

    pub fn as_rule_with_actions_mut(&mut self) -> Option<&mut RuleWithActions> {
        match self {
            Rule::WithActions(r) => Some(r),
            Rule::Marker(_) => None,
        }
    }

    /// `dynamic_cast<RuleWithOperator *>`: the id of a `SecRule`.
    pub fn rule_with_operator_id(&self) -> Option<i64> {
        match self {
            Rule::WithActions(r) if r.is_rule_with_operator() => Some(r.rule_id),
            _ => None,
        }
    }
}
