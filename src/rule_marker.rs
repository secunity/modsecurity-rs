//! Port of `headers/modsecurity/rule_marker.h` (`SecMarker`).

use crate::modsecurity::Phases;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct RuleMarker {
    pub file_name: String,
    pub line_number: i32,
    /// FIXME (C++): phase may not be needed for SecMarker.
    pub phase: i32,
    pub name: String,
}

impl RuleMarker {
    pub fn new(name: &str, file_name: &str, line_number: i32) -> Self {
        RuleMarker {
            file_name: file_name.to_string(),
            line_number,
            phase: Phases::RequestHeadersPhase as i32,
            name: name.to_string(),
        }
    }

    /// Leaves the marker section the transaction was skipping to, if this
    /// is the marker it was looking for.
    pub fn evaluate(&self, t: &mut Transaction<'_>) -> bool {
        if t.is_inside_a_marker() && t.get_current_marker() == Some(self.name.as_str()) {
            t.remove_marker();
            // FIXME (C++): ms_dbg_a(transaction, 4, "Out of a SecMarker " + *m_name);
        }
        true
    }
}
