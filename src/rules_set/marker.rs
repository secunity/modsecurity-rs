//! A `SecMarker`: the target of `skipAfter`.

use crate::phases::Phases;

#[derive(Debug)]
pub struct Marker {
    pub file_name: String,
    pub line_number: usize,
    /// The phase whose list this copy is in (a marker is added to every phase).
    pub phase: Phases,
    pub name: String,
}

impl Marker {
    pub fn new(name: &str, file_name: &str, line_number: usize) -> Self {
        Marker { file_name: file_name.to_string(), line_number, phase: Phases::RequestHeaders, name: name.to_string() }
    }
}
