//! The message a rule produces: what the error log and the audit log
//! report about a match.
//!
//! In C++ a `RuleMessage` holds references to its rule *and* to the
//! transaction, and copies of it are stored inside that same transaction
//! (`m_rulesMessages`). Rust cannot express that self reference, so the
//! message borrows only the rule (which outlives the transaction) and the
//! transaction is passed to the formatting functions instead.

use std::borrow::Cow;

use crate::operators::operator::Operator;
use crate::rule::with_actions::RuleWithActions;
use crate::transaction::Transaction;
use crate::utils::string::{limit_to, to_hex_if_needed};
use crate::variables::variable_value::VariableValue;

bitflags::bitflags! {
    /// The optional parts of a log line ([`RuleMessage::log`]). The bits
    /// are those of the C++ `LogMessageInfo` enumeration.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct LogParts: u8 {
        /// Ends the line with the error log tail (the server name, the URI
        /// and the unique id).
        const ERROR_LOG_TAIL = 2;
        /// Starts the line with `[client <address>]`.
        const CLIENT = 4;
    }
}

/// A match of a rule's operator: what the match message is made of. Most
/// matches are never logged, so the text is only built on demand.
#[derive(Debug, Clone)]
pub struct Matched<'r> {
    pub(crate) operator: &'r dyn Operator,
    /// The operator's parameter as shown in the message, at match time.
    pub(crate) param: Cow<'r, [u8]>,
    /// The variable that matched (before transformations).
    pub(crate) value: VariableValue,
}

#[derive(Debug, Clone)]
pub struct RuleMessage<'r> {
    pub(crate) rule: &'r RuleWithActions,
    pub(crate) data: Vec<u8>,
    pub(crate) is_disruptive: bool,
    /// The last match of the rule's operator, if any (see
    /// [`RuleMessage::match_message`]).
    pub(crate) matched: Option<Matched<'r>>,
    pub(crate) message: Vec<u8>,
    pub(crate) no_audit_log: bool,
    pub(crate) reference: Vec<u8>,
    pub(crate) save_message: bool,
    pub(crate) severity: i32,
    pub(crate) tags: Vec<Vec<u8>>,
}

impl<'r> RuleMessage<'r> {
    pub(crate) fn new(rule: &'r RuleWithActions) -> Self {
        let mut rm = RuleMessage {
            rule,
            data: Vec::new(),
            is_disruptive: false,
            matched: None,
            message: Vec::new(),
            no_audit_log: false,
            reference: Vec::new(),
            save_message: true,
            severity: 0,
            tags: Vec::new(),
        };
        rm.reset(true);
        rm
    }

    pub(crate) fn reset(&mut self, reset_save_message: bool) {
        self.data.clear();
        self.is_disruptive = false;
        self.matched = None;
        self.message.clear();
        self.no_audit_log = false;
        self.reference.clear();
        if reset_save_message {
            self.save_message = true;
        }
        self.severity = 0;
        self.tags.clear();
    }

    /// The match message: `Matched "Operator ..." against variable ...`;
    /// empty when the operator did not match.
    pub fn match_message(&self) -> Vec<u8> {
        self.matched.as_ref().map_or_else(Vec::new, |m| {
            m.operator.resolve_match_message(&m.param, m.value.key_with_collection(), m.value.value())
        })
    }

    /// The log line of the message, with the optional `parts`. `code` is
    /// the status code of a disruptive message; without one the line keeps
    /// a `%d` placeholder for it.
    pub fn log(&self, t: &Transaction<'_>, parts: LogParts, code: Option<i32>) -> String {
        let mut msg: Vec<u8> = Vec::with_capacity(2048);
        if parts.contains(LogParts::CLIENT) {
            msg.extend_from_slice(format!("[client {}] ", t.http.client_ip_address).as_bytes());
        }
        if self.is_disruptive {
            msg.extend_from_slice(b"ModSecurity: Access denied with code ");
            match code {
                Some(code) => msg.extend_from_slice(code.to_string().as_bytes()),
                None => msg.extend_from_slice(b"%d"),
            }
            msg.extend_from_slice(format!(" (phase {}). ", self.phase_number()).as_bytes());
        } else {
            msg.extend_from_slice(b"ModSecurity: Warning. ");
        }
        msg.extend_from_slice(&self.match_message());
        msg.extend_from_slice(&Self::details(self, t));
        if parts.contains(LogParts::ERROR_LOG_TAIL) {
            msg.push(b' ');
            msg.extend_from_slice(&Self::error_log_tail(t));
        }
        to_hex_if_needed(&msg, false)
    }

    /// The error log line: [`Self::log`] with the client address and the
    /// error log tail.
    pub fn error_log(&self, t: &Transaction<'_>) -> String {
        self.log(t, LogParts::CLIENT | LogParts::ERROR_LOG_TAIL, None)
    }

    /// The details of the log line: ` [file "..."] [line "..."] ...`.
    pub(crate) fn details(rm: &RuleMessage<'_>, t: &Transaction<'_>) -> Vec<u8> {
        let r = rm.rule;
        let mut msg: Vec<u8> = Vec::new();
        let mut push = |s: &[u8]| msg.extend_from_slice(s);
        push(format!(" [file \"{}\"]", r.file_name).as_bytes());
        push(format!(" [line \"{}\"]", r.line_number).as_bytes());
        push(format!(" [id \"{}\"]", r.rule_id).as_bytes());
        push(format!(" [rev \"{}\"]", to_hex_if_needed(r.rev.as_bytes(), true)).as_bytes());
        push(b" [msg \"");
        push(&rm.message);
        push(b"\"]");
        push(format!(" [data \"{}\"]", to_hex_if_needed(&limit_to(200, &rm.data), true)).as_bytes());
        push(format!(" [severity \"{}\"]", rm.severity).as_bytes());
        push(format!(" [ver \"{}\"]", to_hex_if_needed(r.ver.as_bytes(), true)).as_bytes());
        push(format!(" [maturity \"{}\"]", r.maturity).as_bytes());
        push(format!(" [accuracy \"{}\"]", r.accuracy).as_bytes());
        for a in &rm.tags {
            push(format!(" [tag \"{}\"]", to_hex_if_needed(a, true)).as_bytes());
        }
        push(b" [hostname \"");
        push(t.http.request_host_name.as_bytes());
        push(b"\"]");
        push(b" [uri \"");
        push(&limit_to(200, &t.http.uri_no_query_string_decoded));
        push(b"\"]");
        push(format!(" [unique_id \"{}\"]", t.id).as_bytes());
        push(b" [ref \"");
        push(&limit_to(200, &rm.reference));
        push(b"\"]");
        msg
    }

    /// The tail of an error log line: the server address (as `hostname`),
    /// the uri and the unique id.
    pub(crate) fn error_log_tail(t: &Transaction<'_>) -> Vec<u8> {
        let mut msg: Vec<u8> = Vec::new();
        msg.extend_from_slice(format!("[hostname \"{}\"]", t.http.server_ip_address).as_bytes());
        msg.extend_from_slice(b" [uri \"");
        msg.extend_from_slice(&limit_to(200, &t.http.uri_no_query_string_decoded));
        msg.extend_from_slice(b"\"]");
        msg.extend_from_slice(format!(" [unique_id \"{}\"]", t.id).as_bytes());
        msg
    }

    /// The `id` of the rule (0 for rules without one).
    pub fn rule_id(&self) -> i64 {
        self.rule.rule_id
    }

    /// The SecLang phase number (1..5) of the rule.
    pub fn phase_number(&self) -> i32 {
        // C++ `m_phase - 1`, with -1 as the phase of an unknown name.
        self.rule.phase().map_or(-1, |p| p as i32) - 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instance::{LogProperties, ModSecurity, ServerLogEntry};
    use crate::rules_set::RulesSet;
    use std::sync::{Arc, Mutex};

    /// Runs a request that the rule `actions` matches; returns what the
    /// server log callback received with `properties`, and the log of the
    /// intervention.
    fn logged(properties: LogProperties, actions: &str) -> (Vec<String>, Option<String>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut ms = ModSecurity::new();
        let sink = seen.clone();
        ms.set_server_log_cb_with_properties(
            Box::new(move |_, entry| {
                let line = match entry {
                    ServerLogEntry::Text(text) => format!("text: {text}"),
                    ServerLogEntry::RuleMessage(rm, t) => format!(
                        "message {}: {} | {} | {}",
                        rm.rule_id(),
                        rm.log(t, LogParts::empty(), None),
                        rm.log(t, LogParts::CLIENT, None),
                        rm.log(t, LogParts::CLIENT | LogParts::ERROR_LOG_TAIL, None) == rm.error_log(t),
                    ),
                };
                sink.lock().unwrap().push(line);
            }),
            properties,
        );
        let mut rules = RulesSet::new();
        rules.load(&format!("SecRuleEngine On\nSecRule ARGS \"@streq x\" \"id:7,phase:1,{actions}\"\n")).unwrap();
        let mut t = Transaction::new(&ms, &rules, None);
        t.process_connection("192.0.2.1", 1, "127.0.0.1", 80);
        t.process_uri(b"/?a=x", b"GET", b"1.1");
        t.process_request_headers();
        let intervention = t.intervention().and_then(|it| it.log);
        drop(t);
        let lines = seen.lock().unwrap().clone();
        (lines, intervention)
    }

    #[test]
    fn log_properties_and_parts() {
        // Messages that do not disrupt go to the server log.
        let (text, _) = logged(LogProperties::TEXT, "pass,log");
        assert_eq!(text.len(), 1);
        assert!(text[0].starts_with("text: ModSecurity: Warning. Matched "), "{text:?}");
        // The text wins when both are asked for, as in C++.
        let (both, _) = logged(LogProperties::TEXT | LogProperties::RULE_MESSAGE, "pass,log");
        assert!(both.len() == 1 && both[0].starts_with("text: "), "{both:?}");

        let (message, _) = logged(LogProperties::RULE_MESSAGE, "pass,log");
        assert_eq!(message.len(), 1);
        let parts: Vec<&str> = message[0].split(" | ").collect();
        assert!(parts[0].starts_with("message 7: ModSecurity: Warning. Matched "), "{message:?}");
        assert!(parts[1].starts_with("[client 192.0.2.1] ModSecurity: Warning. Matched "), "{message:?}");
        assert_eq!(parts[2], "true");

        assert!(logged(LogProperties::empty(), "pass,log").0.is_empty());

        // A disruptive message is the log of the intervention: the client
        // part, and the status in place of the `%d` left without a code.
        let (lines, intervention) = logged(LogProperties::TEXT, "deny,status:403,log");
        assert!(lines.is_empty());
        let intervention = intervention.unwrap();
        assert!(
            intervention.starts_with("[client 192.0.2.1] ModSecurity: Access denied with code 403 (phase 1). "),
            "{intervention}"
        );

        // The bits of the C++ enumerations.
        assert_eq!(
            (
                LogProperties::TEXT.bits(),
                LogProperties::RULE_MESSAGE.bits(),
                LogProperties::INCLUDE_FULL_HIGHLIGHT.bits()
            ),
            (1, 2, 4)
        );
        assert_eq!((LogParts::ERROR_LOG_TAIL.bits(), LogParts::CLIENT.bits()), (2, 4));
    }
}
