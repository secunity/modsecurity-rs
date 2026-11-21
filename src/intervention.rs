//! A disruptive action of the rules: [`Intervention`], what a transaction
//! hands out, and [`PendingIntervention`], what the rules build until then.
//! (The C API exchanges it as `capi::intervention::ModSecurityIntervention`.)

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

/// The log of a pending intervention.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InterventionLog {
    /// A fixed message (a body limit that rejects).
    Text(&'static str),
    /// The log line of the rule message that disrupted, in two parts: the
    /// status code goes between them when the intervention is handed out
    /// (`... Access denied` `with code 403` ` (phase 1). ...`).
    RuleMessage { before_code: String, after_code: String },
}

impl InterventionLog {
    /// The log text, with `status` as the status code of a rule message.
    pub(crate) fn render(&self, status: u16) -> String {
        match self {
            InterventionLog::Text(text) => (*text).to_string(),
            InterventionLog::RuleMessage { before_code, after_code } => {
                format!("{before_code} with code {status}{after_code}")
            }
        }
    }
}

/// The intervention the rules are deciding, until the transaction hands
/// it out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingIntervention {
    /// The HTTP status code (200 until a `status` or disruptive action
    /// sets one).
    pub(crate) status: u16,
    /// The redirect target (`redirect` action), as raw bytes.
    pub(crate) url: Option<Vec<u8>>,
    pub(crate) log: Option<InterventionLog>,
    /// Whether the transaction has to be interrupted.
    pub(crate) disruptive: bool,
}

impl Default for PendingIntervention {
    fn default() -> Self {
        PendingIntervention { status: 200, url: None, log: None, disruptive: false }
    }
}

impl PendingIntervention {
    /// Clears the status and the disruptive flag but keeps `url` and `log`
    /// (a later disruptive action replaces them).
    pub(crate) fn reset(&mut self) {
        self.status = 200;
        self.disruptive = false;
    }

    /// The intervention as it is handed out: the log gets the status code.
    pub(crate) fn to_intervention(&self) -> Intervention {
        Intervention {
            status: self.status,
            url: self.url.clone(),
            log: self.log.as_ref().map(|log| log.render(self.status)),
            disruptive: self.disruptive,
        }
    }
}
