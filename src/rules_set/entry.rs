//! An entry of a rule set: a rule, or a `SecMarker` (a position in the
//! list that `skipAfter` jumps to).

use crate::phases::Phases;
use crate::rule::Rule;
use crate::rules_set::marker::Marker;

// Entries always live behind an `Arc`, so the size difference between the
// variants does not matter.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum Entry {
    Marker(Marker),
    Rule(Rule),
}

impl Entry {
    /// The phase the entry is in.
    pub fn phase(&self) -> Phases {
        match self {
            Entry::Marker(m) => m.phase,
            Entry::Rule(r) => r.phase(),
        }
    }

    /// How the logs refer to the entry: its id for a `SecRule`,
    /// `file:line` otherwise.
    pub fn reference(&self) -> String {
        match self {
            Entry::Marker(m) => format!("{}:{}", m.file_name, m.line_number),
            Entry::Rule(r) => r.reference(),
        }
    }

    /// The marker, unless this is a rule.
    pub fn as_marker(&self) -> Option<&Marker> {
        match self {
            Entry::Marker(m) => Some(m),
            Entry::Rule(_) => None,
        }
    }

    /// The rule, unless this is a marker.
    pub fn as_rule(&self) -> Option<&Rule> {
        match self {
            Entry::Rule(r) => Some(r),
            Entry::Marker(_) => None,
        }
    }

    pub fn as_rule_mut(&mut self) -> Option<&mut Rule> {
        match self {
            Entry::Rule(r) => Some(r),
            Entry::Marker(_) => None,
        }
    }

    /// The id of a `SecRule`; `None` for any other rule.
    pub fn sec_rule_id(&self) -> Option<crate::rule::Id> {
        match self {
            Entry::Rule(r) if r.is_sec_rule() => r.rule_id,
            _ => None,
        }
    }
}
