//! A pending disruptive action: [`Intervention`]. (The C API exchanges it
//! as `capi::intervention::ModSecurityIntervention`.)

/// A disruptive action requested by the rules (`deny`, `drop`, `redirect`,
/// or a body limit set to `Reject`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Intervention {
    /// The HTTP status code to answer with.
    pub status: u16,
    /// The redirect target (`redirect` action), as raw bytes.
    pub url: Option<Vec<u8>>,
    /// The log message (`[client ...] ModSecurity: Access denied ...`).
    pub log: Option<String>,
    /// Whether the transaction has to be interrupted.
    pub disruptive: bool,
}

impl Default for Intervention {
    fn default() -> Self {
        Intervention { status: 200, url: None, log: None, disruptive: false }
    }
}

impl Intervention {
    /// Clears the status and the disruptive flag but keeps `url` and `log`
    /// (a later disruptive action replaces them).
    pub(crate) fn reset(&mut self) {
        self.status = 200;
        self.disruptive = false;
    }
}
