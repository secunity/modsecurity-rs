//! The message of a rule that matched: what the engine reports about it.
//!
//! A [`RuleMessage`] is the event itself, as data: the rule, what it says
//! about the match (`msg`, `logdata`, `severity`, `tag`s), and what
//! matched. An embedder reads it from
//! [`Transaction::rule_messages`](crate::Transaction::rule_messages), or
//! receives it from the server log callback
//! ([`LogProperties::RULE_MESSAGE`](crate::LogProperties)).
//!
//! The logs are renderings of it: the error log line and the `H` part of
//! the native audit log (`text.rs`), and the `messages` of the JSON audit
//! log (`json.rs`). The request they mention (client, host, URI, unique
//! id) is taken from the transaction.
//!
//! While its rule is evaluated the message is also where the actions
//! write (`ActionContext`); it borrows the rule, which outlives every
//! transaction.

mod json;
mod text;

use std::borrow::Cow;

use crate::operators::operator::Operator;
use crate::rule::Rule;
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
    pub(crate) operator: &'r Operator,
    /// The operator's parameter as shown in the message, at match time.
    pub(crate) param: Cow<'r, [u8]>,
    /// The variable that matched (before transformations).
    pub(crate) value: VariableValue,
}

#[derive(Debug, Clone)]
pub struct RuleMessage<'r> {
    pub(crate) rule: &'r Rule,
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
    pub(crate) fn new(rule: &'r Rule) -> Self {
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

    // --- the rule ---

    /// The `id` of the rule (0 for rules without one).
    pub fn rule_id(&self) -> i64 {
        self.rule.rule_id.get()
    }

    /// The file the rule was read from, and its line there.
    pub fn rule_location(&self) -> (&'r str, i32) {
        (&self.rule.file_name, self.rule.line_number)
    }

    /// The `rev` of the rule.
    pub fn rev(&self) -> &'r str {
        &self.rule.rev
    }

    /// The `ver` of the rule.
    pub fn ver(&self) -> &'r str {
        &self.rule.ver
    }

    /// The `maturity` of the rule.
    pub fn maturity(&self) -> i32 {
        self.rule.maturity
    }

    /// The `accuracy` of the rule.
    pub fn accuracy(&self) -> i32 {
        self.rule.accuracy
    }

    // --- what the rule says about the match ---

    /// The `msg` of the rule, with its macros expanded.
    pub fn message(&self) -> &[u8] {
        &self.message
    }

    /// The `logdata` of the rule, with its macros expanded.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// The `severity` of the rule (0 to 7; 0 also without one).
    pub fn severity(&self) -> i32 {
        self.severity
    }

    /// The `tag`s of the rule, with their macros expanded.
    pub fn tags(&self) -> impl Iterator<Item = &[u8]> {
        self.tags.iter().map(Vec::as_slice)
    }

    /// Whether the rule interrupted the transaction (`deny`, `drop`,
    /// `redirect`): the message is then the log of the intervention.
    pub fn is_disruptive(&self) -> bool {
        self.is_disruptive
    }

    // --- what matched ---

    /// The name of the operator that matched (`Rx`, `Pm`, ...); `None`
    /// for a rule without one (`SecAction`).
    pub fn operator(&self) -> Option<&'static str> {
        self.matched.as_ref().map(|m| m.operator.name())
    }

    /// The parameter of the operator, as the match message shows it.
    pub fn operator_parameter(&self) -> Option<&[u8]> {
        self.matched.as_ref().map(|m| &*m.param)
    }

    /// The variable that matched, with its collection
    /// (`ARGS:name`), and its value before the transformations.
    pub fn variable(&self) -> Option<(&[u8], &[u8])> {
        self.matched.as_ref().map(|m| (m.value.key_with_collection(), m.value.value()))
    }

    /// Where the match is in the request: the offsets of the variable and
    /// of the match in it, and the transformations
    /// (`o0,4v64,13t:lowercase`, see
    /// [`ModSecurity::process_content_offset`](crate::ModSecurity::process_content_offset)).
    pub fn reference(&self) -> &[u8] {
        &self.reference
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
    use crate::transaction::Transaction;
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

    /// A match read as data, without parsing a log line: from the
    /// transaction (every message, the disruptive one too) and from the
    /// server log callback.
    #[test]
    fn a_message_as_data() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut ms = ModSecurity::new();
        let sink = seen.clone();
        ms.set_server_log_cb_with_properties(
            Box::new(move |_, entry| {
                if let ServerLogEntry::RuleMessage(rm, _) = entry {
                    sink.lock().unwrap().push((rm.rule_id(), rm.message().to_vec(), rm.severity()));
                }
            }),
            LogProperties::RULE_MESSAGE,
        );
        let mut rules = RulesSet::new();
        rules
            .load_with_ref(
                "SecRuleEngine On\n\
                 SecRule ARGS:q \"@contains select\" \"id:10,phase:1,pass,log,t:lowercase,rev:'3',ver:'v1',maturity:8,\\\n\
                 accuracy:9,msg:'SQL in %{MATCHED_VAR_NAME}',logdata:'%{MATCHED_VAR}',severity:2,tag:'attack-sqli',tag:'app'\"\n\
                 SecRule ARGS:q \"@rx (?i)union\" \"id:11,phase:1,deny,status:403,msg:'blocked'\"\n",
                "events.conf",
            )
            .unwrap();
        let mut t = Transaction::new(&ms, &rules, None);
        t.process_uri(b"/?q=SELECT+1+UNION", b"GET", b"1.1");
        t.process_request_headers();

        let messages = t.rule_messages();
        assert_eq!(messages.len(), 2);
        let warning = &messages[0];
        assert_eq!((warning.rule_id(), warning.is_disruptive()), (10, false));
        assert_eq!(warning.rule_location().0, "events.conf");
        assert_eq!((warning.rev(), warning.ver(), warning.maturity(), warning.accuracy()), ("3", "v1", 8, 9));
        assert_eq!(warning.message(), b"SQL in ARGS:q");
        assert_eq!(warning.data(), b"select 1 union");
        assert_eq!(warning.severity(), 2);
        assert_eq!(warning.tags().collect::<Vec<_>>(), [&b"attack-sqli"[..], b"app"]);
        assert_eq!(warning.operator(), Some("Contains"));
        assert_eq!(warning.operator_parameter(), Some(&b"select"[..]));
        // The variable as it was sent, before `t:lowercase`.
        assert_eq!(warning.variable(), Some((&b"ARGS:q"[..], &b"SELECT 1 UNION"[..])));
        assert!(warning.reference().starts_with(b"o0,6v"), "{:?}", String::from_utf8_lossy(warning.reference()));

        let denial = &messages[1];
        assert_eq!((denial.rule_id(), denial.is_disruptive(), denial.message()), (11, true, &b"blocked"[..]));
        assert_eq!(denial.operator(), Some("Rx"));

        // The callback gets the messages that do not interrupt.
        assert_eq!(*seen.lock().unwrap(), [(10, b"SQL in ARGS:q".to_vec(), 2)]);
    }
}
