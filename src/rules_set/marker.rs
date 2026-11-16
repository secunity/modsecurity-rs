//! A `SecMarker`: the target of `skipAfter`.

use crate::phases::Phases;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct Marker {
    pub file_name: String,
    pub line_number: i32,
    /// FIXME (C++): phase may not be needed for SecMarker.
    pub phase: Phases,
    pub name: String,
}

impl Marker {
    pub fn new(name: &str, file_name: &str, line_number: i32) -> Self {
        Marker { file_name: file_name.to_string(), line_number, phase: Phases::RequestHeaders, name: name.to_string() }
    }

    /// Leaves the marker section the transaction was skipping to, if this
    /// is the marker it was looking for.
    pub fn evaluate(&self, t: &mut Transaction<'_>) -> bool {
        if t.is_inside_a_marker() && t.current_marker() == Some(self.name.as_str()) {
            t.remove_marker();
            // FIXME (C++): ms_dbg_a(transaction, 4, "Out of a SecMarker " + *m_name);
        }
        true
    }
}
