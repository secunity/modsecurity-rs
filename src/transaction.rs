//! A transaction: one HTTP request and its response, fed by the connector
//! phase by phase and inspected by the rules.
//!
//! A `Transaction` borrows its `ModSecurity` instance and `RulesSet` for its
//! whole life (`'a`): whoever creates the transaction keeps both alive
//! for as long as it exists. The rule
//! messages it accumulates borrow the rules for the same lifetime.
//!
//! Its state is grouped by what it is for:
//!
//! - `http` ([`HttpData`]): the request and response as the connector
//!   reported them (addresses, URI, bodies, status);
//! - `vars` ([`TransactionVariables`], declared in `variables::table`), `collections` and
//!   `variable_envs`: the variables rules inspect (`ARGS` is
//!   `t.vars.args`);
//! - `body` ([`BodyProcessing`]): the request body processors' state;
//! - `ctl` ([`CtlOverrides`]): the settings rules changed with `ctl:`;
//! - `eval` ([`EvalState`], see `crate::eval`): where rule evaluation is (skips, the
//!   `SecMarker` being skipped to, `allow`, chains, captures);
//! - `outcome` ([`Outcome`]): the intervention and the messages for the
//!   logs.
//!
//! The steps a connector drives are in `request.rs` (connection, URI,
//! headers, body) and `response.rs` (status, headers, body), the argument
//! parsing in `arguments.rs`, the request body processors in `body.rs` and
//! the `ctl:` changes in `ctl.rs`. This file has the state, creating a
//! transaction, running a phase, the body buffers both directions share,
//! the logging phase and the intervention.

mod arguments;
mod body;
mod ctl;
mod request;
mod response;

pub(crate) use ctl::CtlOverrides;
use std::any::Any;
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::collection::collections::Collections;
use crate::eval::EvalState;
use crate::instance::ModSecurity;
use crate::intervention::{Intervention, InterventionLog, PendingIntervention};
use crate::phases::Phases;
use crate::rule::message::RuleMessage;
use crate::rules_set::RulesSet;
use crate::rules_set::properties::{BodyLimitAction, RuleEngine};
pub use crate::variables::table::TransactionVariables;
use modsecurity_body::json::Json;
use modsecurity_body::multipart::MultipartPartTmpFile;
#[cfg(feature = "libxml2")]
use modsecurity_body::xml::Xml;

/// The kind of request body the `Content-Type` header announces (or
/// `ctl:requestBodyProcessor=URLENCODED` sets).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestBodyType {
    /// `multipart/form-data`.
    Multipart,
    /// `application/x-www-form-urlencoded`.
    UrlEncoded,
}

/// The request body processor a rule chose with
/// `ctl:requestBodyProcessor`. It takes precedence over the body type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestBodyProcessor {
    Json,
    Xml,
}

/// Which body a piece is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyDirection {
    Request,
    Response,
}

/// The HTTP exchange as the connector reported it, and what is derived
/// from it directly (decoded URIs, the bodies, the status code).
pub(crate) struct HttpData {
    pub(crate) client_ip_address: String,
    pub(crate) client_port: u16,
    pub(crate) server_ip_address: String,
    pub(crate) server_port: u16,
    pub(crate) request_host_name: String,
    /// The HTTP version: 1.1, 2.0, ...
    pub(crate) http_version: String,
    /// The raw URI that was requested.
    pub(crate) uri: Vec<u8>,
    /// The decoded URI (raw is `uri`).
    pub(crate) uri_decoded: Vec<u8>,
    /// The decoded URI without the query string.
    pub(crate) uri_no_query_string_decoded: Vec<u8>,
    pub(crate) request_body: Vec<u8>,
    pub(crate) response_body: Vec<u8>,
    /// Combined size of all arguments (`ARGS_COMBINED_SIZE`).
    pub(crate) args_combined_size: usize,
    /// The HTTP status code, when known.
    pub(crate) http_code_returned: u16,
}

/// Request body processing: the body's type, the processor chosen for it
/// and the processors' state.
pub(crate) struct BodyProcessing {
    /// From the `Content-Type` (`None`: no type with a processor).
    pub(crate) request_body_type: Option<RequestBodyType>,
    /// From `ctl:requestBodyProcessor` (`None`: none was chosen).
    pub(crate) request_body_processor: Option<RequestBodyProcessor>,
    #[cfg(feature = "libxml2")]
    pub(crate) xml: Option<Box<Xml>>,
    pub(crate) json: Json,
    pub(crate) multipart_part_tmp_files: Vec<Arc<MultipartPartTmpFile>>,
}

/// What the rules decided and reported: the intervention, the messages
/// for the logs, the highest severity.
pub(crate) struct Outcome<'a> {
    /// Messages saved by `log`/`msg`/... for the audit log.
    pub(crate) rules_messages: Vec<RuleMessage<'a>>,
    /// The pending disruptive action, handed out by
    /// [`Transaction::intervention`].
    pub(crate) intervention: PendingIntervention,
    /// Sticky flag set the first time a disruptive intervention is consumed
    /// through [`Transaction::intervention`].
    pub(crate) is_interrupted: bool,
    /// The highest severity (the lowest number) of the rules that matched
    /// so far, set by the `severity` action; see [`Outcome::highest_severity_value`].
    pub(crate) highest_severity: Option<u8>,
}

impl Outcome<'_> {
    /// `HIGHEST_SEVERITY`: 255, above every severity (0 to 7), until a
    /// rule with a severity matched.
    pub(crate) fn highest_severity_value(&self) -> u8 {
        self.highest_severity.unwrap_or(u8::MAX)
    }
}

pub struct Transaction<'a> {
    pub(crate) ms: &'a ModSecurity,
    pub(crate) rules: &'a RulesSet,
    /// The unique ID of the transaction (`UNIQUE_ID`).
    pub(crate) id: String,
    /// Creation time, in seconds since the epoch.
    pub(crate) time_stamp: i64,
    /// CPU time at creation, base of the `DURATION` variable.
    pub(crate) creation_time_stamp: f64,
    pub(crate) http: HttpData,
    pub(crate) vars: TransactionVariables,
    pub(crate) collections: Collections<'a>,
    /// Environment variables set by `setenv`.
    pub(crate) variable_envs: BTreeMap<Vec<u8>, Vec<u8>>,
    pub(crate) body: BodyProcessing,
    pub(crate) ctl: CtlOverrides,
    pub(crate) eval: EvalState<'a>,
    pub(crate) outcome: Outcome<'a>,
    log_cb_data: Option<Box<dyn Any + Send>>,
}

fn transaction_id(id: Option<&str>, timestamp: i64) -> String {
    match id {
        Some(id) => id.to_string(),
        None => format!("{}{:.6}", timestamp, rand::Rng::random_range(&mut rand::rng(), 0.0..100.0)),
    }
}

impl<'a> Transaction<'a> {
    /// A transaction with a generated unique id. `log_cb_data` is handed
    /// to the server log callback.
    pub fn new(ms: &'a ModSecurity, rules: &'a RulesSet, log_cb_data: Option<Box<dyn Any + Send>>) -> Self {
        Self::with_id_and_time(ms, rules, None, log_cb_data, crate::utils::system::now())
    }

    /// A transaction with the unique id `id`.
    pub fn with_id(
        ms: &'a ModSecurity,
        rules: &'a RulesSet,
        id: &str,
        log_cb_data: Option<Box<dyn Any + Send>>,
    ) -> Self {
        Self::with_id_and_time(ms, rules, Some(id), log_cb_data, crate::utils::system::now())
    }

    fn with_id_and_time(
        ms: &'a ModSecurity,
        rules: &'a RulesSet,
        id: Option<&str>,
        log_cb_data: Option<Box<dyn Any + Send>>,
        timestamp: i64,
    ) -> Self {
        let mut t = Transaction {
            ms,
            rules,
            id: transaction_id(id, timestamp),
            time_stamp: timestamp,
            creation_time_stamp: crate::utils::system::cpu_seconds(),
            http: HttpData {
                client_ip_address: String::new(),
                client_port: 0,
                server_ip_address: String::new(),
                server_port: 0,
                request_host_name: String::new(),
                http_version: String::new(),
                uri: Vec::new(),
                uri_decoded: Vec::new(),
                uri_no_query_string_decoded: Vec::new(),
                request_body: Vec::new(),
                response_body: Vec::new(),
                args_combined_size: 0,
                http_code_returned: 200,
            },
            vars: TransactionVariables::new(),
            collections: Collections::new(
                ms.global_collection.as_ref(),
                ms.ip_collection.as_ref(),
                ms.session_collection.as_ref(),
                ms.user_collection.as_ref(),
                ms.resource_collection.as_ref(),
            ),
            variable_envs: BTreeMap::new(),
            body: BodyProcessing {
                request_body_type: None,
                request_body_processor: None,
                #[cfg(feature = "libxml2")]
                xml: Some(Box::new(Xml::new())),
                json: Json::new(),
                multipart_part_tmp_files: Vec::new(),
            },
            ctl: CtlOverrides::new(rules),
            eval: EvalState::default(),
            outcome: Outcome {
                rules_messages: Vec::new(),
                intervention: PendingIntervention::default(),
                is_interrupted: false,
                highest_severity: None,
            },
            log_cb_data,
        };
        t.vars.url_encoded_error.set(b"0", 0);
        t.vars.msc_pcre_error.set(b"0", 0);
        t.vars.msc_pcre_limits_exceeded.set(b"0", 0);
        crate::ms_dbg!(&t, 4, "Initializing transaction");
        t
    }

    fn evaluate_phase(&mut self, phase: Phases) {
        crate::eval::run_phase(self.rules, phase, self);
    }

    /// The request body or the response body kept so far.
    fn body_mut(&mut self, direction: BodyDirection) -> &mut Vec<u8> {
        match direction {
            BodyDirection::Request => &mut self.http.request_body,
            BodyDirection::Response => &mut self.http.response_body,
        }
    }

    /// Adds `buf` to a body. Past the body's limit, `INBOUND_DATA_ERROR`
    /// (`OUTBOUND_DATA_ERROR`) is 1 and the limit action decides:
    ///
    /// - `ProcessPartial`: the body is kept up to the limit; returns
    ///   `false`.
    /// - `Reject`: with the rule engine `On`, the transaction is
    ///   interrupted with a 403. Otherwise the body is kept up to the limit,
    ///   so that rules that only detect see what `On` would reject.
    /// - none: the piece is dropped.
    fn append_body(&mut self, direction: BodyDirection, buf: &[u8]) -> bool {
        let settings = &self.rules.properties.settings;
        let (limit, action, kind) = match direction {
            BodyDirection::Request => (settings.request_body_limit, settings.request_body_limit_action, "Request"),
            BodyDirection::Response => (settings.response_body_limit, settings.response_body_limit_action, "Response"),
        };
        let limit = usize::try_from(limit.unwrap_or(0)).unwrap_or(usize::MAX);
        let current_size = self.body_mut(direction).len();
        if limit == 0 || current_size + buf.len() <= limit {
            self.body_mut(direction).extend_from_slice(buf);
            return true;
        }

        let off = self.vars.offset;
        match direction {
            BodyDirection::Request => self.vars.inbound_data_error.set(b"1", off),
            BodyDirection::Response => self.vars.outbound_data_error.set(b"1", off),
        }
        crate::ms_dbg!(self, 5, "{} body is bigger than the maximum expected.", kind);
        let keep_up_to_limit = |t: &mut Self| {
            let n = limit.saturating_sub(current_size).min(buf.len());
            t.body_mut(direction).extend_from_slice(&buf[..n]);
        };
        match action {
            Some(BodyLimitAction::ProcessPartial) => {
                keep_up_to_limit(self);
                crate::ms_dbg!(self, 5, "{} body limit is marked to process partial", kind);
                false
            }
            Some(BodyLimitAction::Reject) => {
                crate::ms_dbg!(self, 5, "{} body limit is marked to reject the request", kind);
                if self.rule_engine_state() == Some(RuleEngine::Enabled) {
                    let log = match direction {
                        BodyDirection::Request => "Request body limit is marked to reject the request",
                        BodyDirection::Response => "Response body limit is marked to reject the request",
                    };
                    self.outcome.intervention.disrupt(403, None, InterventionLog::Text(log));
                } else {
                    crate::ms_dbg!(self, 5, "Not rejecting the request as the engine is not Enabled");
                    keep_up_to_limit(self);
                }
                true
            }
            None => true,
        }
    }

    /// The messages of the rules that matched so far, in order.
    pub fn rule_messages(&self) -> &[RuleMessage<'a>] {
        &self.outcome.rules_messages
    }

    /// Phase 5: runs the logging rules, then writes the audit log entry
    /// if the transaction is relevant.
    pub fn process_logging(&mut self) {
        crate::ms_dbg!(self, 4, "Starting phase LOGGING. (SecRules 5)");

        if self.rule_engine_state() == Some(RuleEngine::Disabled) {
            crate::ms_dbg!(self, 4, "Rule engine disabled, returning...");
            return;
        }

        self.evaluate_phase(Phases::Logging);

        // If relevant, save this transaction information at the audit_logs
        let audit = &self.rules.properties.audit_log;
        let mut parts = audit.parts();
        crate::ms_dbg!(self, 8, "Checking if this request is suitable to be saved as an audit log.");

        if !self.ctl.audit_log_modifier.is_empty() {
            crate::ms_dbg!(self, 4, "There was an audit log modifier for this transaction.");
            crate::ms_dbg!(self, 7, "AuditLog parts before modification(s): {}.", parts.bits());
            for (op, p) in &self.ctl.audit_log_modifier {
                parts = op.apply(parts, *p);
            }
        }
        crate::ms_dbg!(self, 8, "Checking if this request is relevant to be part of the audit logs.");
        let saved = audit.save_if_relevant(self, parts);
        if saved {
            crate::ms_dbg!(self, 8, "Request was relevant to be saved. Parts: {}", parts.bits());
        }
    }

    /// The pending disruptive intervention, if any, its log with the
    /// status code. Handing it out clears it: a later intervention has only
    /// what its own actions set.
    pub fn intervention(&mut self) -> Option<Intervention> {
        let it = self.outcome.intervention.take()?;
        self.outcome.is_interrupted = true;
        Some(it)
    }

    /// What a persistent collection answered. When its storage failed,
    /// that is written to the debug log and the answer is the empty one:
    /// nothing found, nothing stored.
    pub(crate) fn stored<T: Default>(&self, answer: Result<T, crate::collection::StorageError>) -> T {
        answer.unwrap_or_else(|error| {
            crate::ms_dbg!(self, 1, "Persistent collection: {}", error);
            T::default()
        })
    }

    /// Sends a rule message to the server log callback.
    pub(crate) fn server_log(&self, rm: &RuleMessage<'_>) {
        self.ms.server_log(self.log_cb_data.as_deref(), rm, self);
    }

    /// The rule engine state: this transaction's `ctl:ruleEngine`, else
    /// `SecRuleEngine`.
    pub(crate) fn rule_engine_state(&self) -> Option<RuleEngine> {
        self.ctl.rule_engine.or(self.rules.properties.settings.sec_rule_engine)
    }
}

impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        // Releasing a multipart temp file writes to the debug log, so the
        // files are released here, while the transaction
        // (and its debug log) is still alive.
        let me: &Transaction<'_> = self;
        for f in &me.body.multipart_part_tmp_files {
            f.release(Some(me));
        }
    }
}

/// The debug log of the rule set, with the transaction id and URI on each
/// line.
impl crate::DebugSink for Transaction<'_> {
    fn debug_enabled(&self, level: u8) -> bool {
        self.rules.properties.debug_log.enabled(level)
    }

    fn debug(&self, level: u8, message: &str) {
        self.rules.debug(level, &self.id, &String::from_utf8_lossy(&self.http.uri), message);
    }
}

#[cfg(test)]
mod tests {
    use crate::{ModSecurity, RulesSet, Transaction};

    /// What a transaction made of a request body: the result of adding it
    /// (`added`), the length kept, and the status of the intervention.
    fn outcome(t: &mut Transaction<'_>, added: bool) -> (bool, usize, Option<u16>) {
        (added, t.request_body_length(), t.intervention().map(|it| it.status))
    }

    #[test]
    fn a_body_from_a_file_is_a_body_appended_whole() {
        let dir = std::env::temp_dir().join(format!("modsec-body-file-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ms = ModSecurity::new();
        for config in [
            "",
            "SecRequestBodyLimit 1000\nSecRequestBodyLimitAction ProcessPartial",
            "SecRequestBodyLimit 1000\nSecRequestBodyLimitAction Reject",
        ] {
            let mut rules = RulesSet::new();
            rules.load(&format!("SecRuleEngine On\nSecRequestBodyAccess On\n{config}\n")).unwrap();
            for size in [0, 999, 1000, 1001, 5000] {
                let body: Vec<u8> = (0..size).map(|i| b'a' + (i % 26) as u8).collect();
                let path = dir.join(format!("body-{size}"));
                std::fs::write(&path, &body).unwrap();

                let mut from_file = Transaction::new(&ms, &rules, None);
                let added = from_file.request_body_from_file(path.to_str().unwrap()).unwrap();
                let from_file = outcome(&mut from_file, added);
                let mut appended = Transaction::new(&ms, &rules, None);
                let added = appended.append_request_body(&body);
                assert_eq!(from_file, outcome(&mut appended, added), "{config:?}, {size} bytes");
            }
        }
        let rules = RulesSet::new();
        let mut t = Transaction::new(&ms, &rules, None);
        assert!(t.request_body_from_file(dir.join("absent").to_str().unwrap()).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Past the limit the file is not read: an endless one is read up to
    /// one byte more than the limit.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_body_from_a_file_is_read_up_to_the_limit() {
        let ms = ModSecurity::new();
        let mut rules = RulesSet::new();
        rules.load("SecRequestBodyLimit 1000\nSecRequestBodyLimitAction ProcessPartial\n").unwrap();
        let mut t = Transaction::new(&ms, &rules, None);
        let added = t.request_body_from_file("/dev/zero").unwrap();
        assert_eq!(outcome(&mut t, added), (false, 1000, None));
    }

    /// Runs an exchange through rules with body limits of 5 bytes that
    /// reject; the ids of the rules that matched, and whether the
    /// transaction was interrupted.
    fn run_body_limits(engine: &str, request_body: &[u8], response_body: &[u8]) -> (Vec<crate::rule::Id>, bool) {
        let ms = ModSecurity::new();
        let mut rules = RulesSet::new();
        rules
            .load(&format!(
                "SecRuleEngine {engine}\nSecRequestBodyAccess On\nSecResponseBodyAccess On\n\
                 SecRequestBodyLimit 5\nSecRequestBodyLimitAction Reject\n\
                 SecResponseBodyLimit 5\nSecResponseBodyLimitAction Reject\n\
                 SecRule REQUEST_BODY \"@streq abcde\" \"id:1,phase:2,pass,log\"\n\
                 SecRule INBOUND_DATA_ERROR \"@eq 1\" \"id:2,phase:2,pass,log\"\n\
                 SecRule RESPONSE_BODY \"@streq vwxyz\" \"id:3,phase:4,pass,log\"\n\
                 SecRule OUTBOUND_DATA_ERROR \"@eq 1\" \"id:4,phase:4,pass,log\"\n"
            ))
            .unwrap();
        let mut t = Transaction::new(&ms, &rules, None);
        t.process_uri(b"/", b"POST", b"1.1");
        t.process_request_headers();
        assert!(t.append_request_body(request_body));
        let mut interrupted = t.intervention().is_some();
        t.process_request_body();
        t.process_response_headers(200, "HTTP 1.1");
        assert!(t.append_response_body(response_body));
        interrupted |= t.intervention().is_some();
        t.process_response_body();
        (t.rule_messages().iter().filter_map(|m| m.rule_id()).collect(), interrupted)
    }

    /// Why the response body is not inspected, in words.
    #[test]
    fn response_body_disabled() {
        use crate::actions::block::test_support::{has_log, rules};
        for (access, said) in
            [("SecResponseBodyAccess Off\n", "SecResponseBodyAccess Off"), ("", "no SecResponseBodyAccess")]
        {
            let ms = ModSecurity::new();
            let mut rules = rules();
            rules.load(&format!("SecRuleEngine On\n{access}")).unwrap();
            let mut t = Transaction::new(&ms, &rules, None);
            t.process_response_body();
            assert!(has_log(&t, &format!("Response body is disabled ({said}), returning...")), "{said}");
        }
    }

    /// With `Reject` and an engine that only detects, the rules see the
    /// body up to the limit: what `On` would have rejected.
    #[test]
    fn detection_only_sees_the_body_up_to_the_limit() {
        assert_eq!(run_body_limits("DetectionOnly", b"abcdefghij", b"vwxyz0123"), (vec![1, 2, 3, 4], false));
        assert_eq!(run_body_limits("On", b"abcdefghij", b"vwxyz0123"), (vec![2, 4], true));
        assert_eq!(run_body_limits("DetectionOnly", b"abcde", b"vwxyz"), (vec![1, 3], false));
    }
}
