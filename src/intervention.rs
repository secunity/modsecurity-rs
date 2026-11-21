//! A disruptive action of the rules: [`Intervention`], what a transaction
//! hands out, and [`PendingIntervention`], what the rules build until then.
//! (The C API exchanges it as `capi::intervention::ModSecurityIntervention`.)

/// A disruptive action requested by the rules (`deny`, `drop`, `redirect`,
/// or a body limit set to `Reject`): the transaction is to be interrupted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Intervention {
    /// The HTTP status code to answer with.
    pub status: u16,
    /// The redirect target (`redirect` action), as raw bytes.
    pub url: Option<Vec<u8>>,
    /// The log message (`[client ...] ModSecurity: Access denied ...`).
    pub log: String,
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

/// What the rules decided so far about interrupting the transaction,
/// until the transaction hands the intervention out.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) enum PendingIntervention {
    /// Nothing.
    #[default]
    None,
    /// A `status` action set the status a later disruptive action
    /// answers with.
    Status(u16),
    /// A disruptive action interrupts the transaction. (A `status` action
    /// of a later rule still changes the status until it is handed out.)
    Disruptive { status: u16, url: Option<Vec<u8>>, log: InterventionLog },
}

impl PendingIntervention {
    /// The status set so far, by a `status` or a disruptive action.
    pub(crate) fn status(&self) -> Option<u16> {
        match self {
            PendingIntervention::None => None,
            PendingIntervention::Status(status) | PendingIntervention::Disruptive { status, .. } => Some(*status),
        }
    }

    /// `status`: sets the status, of the disruption too if there is one.
    pub(crate) fn set_status(&mut self, new: u16) {
        match self {
            PendingIntervention::Disruptive { status, .. } => *status = new,
            _ => *self = PendingIntervention::Status(new),
        }
    }

    /// A disruptive action: it replaces whatever was pending.
    pub(crate) fn disrupt(&mut self, status: u16, url: Option<Vec<u8>>, log: InterventionLog) {
        *self = PendingIntervention::Disruptive { status, url, log };
    }

    pub(crate) fn is_disruptive(&self) -> bool {
        matches!(self, PendingIntervention::Disruptive { .. })
    }

    /// Hands out a disruptive intervention, its log with the status code,
    /// and clears it. A status without a disruption stays pending.
    pub(crate) fn take(&mut self) -> Option<Intervention> {
        match std::mem::take(self) {
            PendingIntervention::Disruptive { status, url, log } => {
                Some(Intervention { status, url, log: log.render(status) })
            }
            other => {
                *self = other;
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instance::ModSecurity;
    use crate::rules_set::RulesSet;
    use crate::transaction::Transaction;

    #[test]
    fn pending_states() {
        let mut p = PendingIntervention::default();
        assert_eq!((p.status(), p.take()), (None, None));
        p.set_status(404);
        assert_eq!((p.status(), p.take()), (Some(404), None));
        assert_eq!(p, PendingIntervention::Status(404), "a status alone stays pending");
        p.disrupt(302, Some(b"/a".to_vec()), InterventionLog::Text("x"));
        p.set_status(301);
        let it = p.take().unwrap();
        assert_eq!((it.status, it.url.as_deref(), it.log.as_str()), (301, Some(&b"/a"[..]), "x"));
        assert_eq!(p, PendingIntervention::None);
    }

    /// An intervention handed out leaves nothing behind: a later one has
    /// only what its own action set.
    #[test]
    fn a_later_intervention_has_no_url_of_an_earlier_redirect() {
        let ms = ModSecurity::new();
        let mut rules = RulesSet::new();
        rules
            .load(
                "SecRuleEngine On\n\
                 SecRule REQUEST_URI \"@contains go\" \"id:1,phase:1,redirect:/elsewhere\"\n\
                 SecRule REQUEST_HEADERS:X-Test \"@streq deny\" \"id:2,phase:2,deny\"\n",
            )
            .unwrap();
        let mut t = Transaction::new(&ms, &rules, None);
        t.process_uri(b"/go", b"GET", b"1.1");
        t.add_request_header(b"X-Test", b"deny");
        t.process_request_headers();
        let redirect = t.intervention().unwrap();
        assert_eq!((redirect.status, redirect.url.as_deref()), (302, Some(&b"/elsewhere"[..])));
        assert_eq!(t.intervention(), None);
        t.process_request_body();
        let deny = t.intervention().unwrap();
        assert_eq!((deny.status, deny.url), (403, None));
        assert!(deny.log.contains("[id \"2\"]"));
    }
}
