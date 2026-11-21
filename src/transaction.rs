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
//! - `vars` ([`TransactionAnchoredVariables`]), `collections` and
//!   `variable_envs`: the variables rules inspect (`ARGS` is
//!   `t.vars.args`);
//! - `body` ([`BodyProcessing`]): the request body processors' state;
//! - `ctl` ([`CtlOverrides`]): the settings rules changed with `ctl:`;
//! - `eval` ([`EvalState`]): where rule evaluation is (skips, the
//!   `SecMarker` being skipped to, `allow`, chains, captures);
//! - `outcome` ([`Outcome`]): the intervention and the messages for the
//!   logs.

mod arguments;
mod body;

use arguments::ArgumentWriter;
use std::any::Any;
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::actions::disruptive::allow::AllowType;
use crate::audit_log::{AuditLogStatus, Parts, PartsChange};
use crate::collection::collections::Collections;
use crate::instance::ModSecurity;
use crate::intervention::{Intervention, InterventionLog, PendingIntervention};
use crate::phases::Phases;
use crate::rule::message::RuleMessage;
use crate::rule::{Rule, TransformationResults};
use crate::rules_set::RulesSet;
use crate::rules_set::properties::{BodyLimitAction, ParseXmlIntoArgs, RuleEngine, config_boolean_code};
use crate::utils::string::{is_space, split, ssplit};
use crate::variables::anchored_set_variable::AnchoredSetVariable;
use crate::variables::anchored_set_variable_translation_proxy::AnchoredSetVariableTranslationProxy;
use crate::variables::anchored_variable::AnchoredVariable;
use crate::variables::variable::Variable;
use crate::variables::variable_value::VariableValue;
use modsecurity_body::json::Json;
use modsecurity_body::multipart::MultipartPartTmpFile;
#[cfg(feature = "libxml2")]
use modsecurity_body::xml::Xml;
use modsecurity_transformations::url::uri_decode;

/// Types of request body that ModSecurity may give a special treatment for
/// the data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestBodyType {
    UnknownFormat,
    MultiPartRequestBody,
    WWWFormUrlEncoded,
    JSONRequestBody,
    XMLRequestBody,
}

/// Which body a piece is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyDirection {
    Request,
    Response,
}

/// The request/response variables filled while the transaction is
/// processed.
#[derive(Debug, Clone)]
pub struct TransactionAnchoredVariables {
    pub request_headers_names: AnchoredSetVariable,
    pub response_content_type: AnchoredVariable,
    pub response_headers_names: AnchoredSetVariable,
    pub args_combined_size: AnchoredVariable,
    pub auth_type: AnchoredVariable,
    pub files_combined_size: AnchoredVariable,
    pub full_request: AnchoredVariable,
    pub full_request_length: AnchoredVariable,
    pub inbound_data_error: AnchoredVariable,
    pub matched_var: AnchoredVariable,
    pub matched_var_name: AnchoredVariable,
    pub msc_pcre_error: AnchoredVariable,
    pub msc_pcre_limits_exceeded: AnchoredVariable,
    pub multipart_boundary_quoted: AnchoredVariable,
    pub multipart_boundary_white_space: AnchoredVariable,
    pub multipart_crlf_lf_lines: AnchoredVariable,
    pub multipart_data_after: AnchoredVariable,
    pub multipart_data_before: AnchoredVariable,
    pub multipart_duplicate_part_header: AnchoredVariable,
    pub multipart_file_limit_exceeded: AnchoredVariable,
    pub multipart_header_folding: AnchoredVariable,
    pub multipart_invalid_header_folding: AnchoredVariable,
    pub multipart_invalid_part: AnchoredVariable,
    pub multipart_invalid_quoting: AnchoredVariable,
    pub multipart_lf_line: AnchoredVariable,
    pub multipart_missing_semicolon: AnchoredVariable,
    pub multipart_strict_error: AnchoredVariable,
    pub multipart_unmatched_boundary: AnchoredVariable,
    pub outbound_data_error: AnchoredVariable,
    pub path_info: AnchoredVariable,
    pub query_string: AnchoredVariable,
    pub remote_addr: AnchoredVariable,
    pub remote_host: AnchoredVariable,
    pub remote_port: AnchoredVariable,
    pub reqbody_error: AnchoredVariable,
    pub reqbody_error_msg: AnchoredVariable,
    pub reqbody_processor_error: AnchoredVariable,
    pub reqbody_processor_error_msg: AnchoredVariable,
    pub reqbody_processor: AnchoredVariable,
    pub request_basename: AnchoredVariable,
    pub request_body: AnchoredVariable,
    pub request_body_length: AnchoredVariable,
    pub request_filename: AnchoredVariable,
    pub request_line: AnchoredVariable,
    pub request_method: AnchoredVariable,
    pub request_protocol: AnchoredVariable,
    pub request_uri: AnchoredVariable,
    pub request_uri_raw: AnchoredVariable,
    pub resource: AnchoredVariable,
    pub response_body: AnchoredVariable,
    pub response_content_length: AnchoredVariable,
    pub response_protocol: AnchoredVariable,
    pub response_status: AnchoredVariable,
    pub server_addr: AnchoredVariable,
    pub server_name: AnchoredVariable,
    pub server_port: AnchoredVariable,
    pub session_id: AnchoredVariable,
    pub unique_id: AnchoredVariable,
    pub url_encoded_error: AnchoredVariable,
    pub user_id: AnchoredVariable,
    pub args: AnchoredSetVariable,
    pub args_get: AnchoredSetVariable,
    pub args_post: AnchoredSetVariable,
    pub files_sizes: AnchoredSetVariable,
    pub files_names: AnchoredSetVariable,
    pub files_tmp_content: AnchoredSetVariable,
    pub multipart_file_name: AnchoredSetVariable,
    pub multipart_file_name_charset: AnchoredSetVariable,
    pub multipart_file_name_language: AnchoredSetVariable,
    pub multipart_name: AnchoredSetVariable,
    pub matched_vars_names: AnchoredSetVariable,
    pub matched_vars: AnchoredSetVariable,
    pub files: AnchoredSetVariable,
    pub request_cookies: AnchoredSetVariable,
    pub request_headers: AnchoredSetVariable,
    pub response_headers: AnchoredSetVariable,
    pub geo: AnchoredSetVariable,
    pub request_cookies_names: AnchoredSetVariable,
    pub files_tmp_names: AnchoredSetVariable,
    pub multipart_part_headers: AnchoredSetVariable,
    pub offset: usize,
    pub args_names: AnchoredSetVariableTranslationProxy,
    pub args_get_names: AnchoredSetVariableTranslationProxy,
    pub args_post_names: AnchoredSetVariableTranslationProxy,
}

impl Default for TransactionAnchoredVariables {
    fn default() -> Self {
        Self::new()
    }
}

impl TransactionAnchoredVariables {
    pub fn new() -> Self {
        let a = AnchoredVariable::new;
        let s = AnchoredSetVariable::new;
        TransactionAnchoredVariables {
            request_headers_names: s("REQUEST_HEADERS_NAMES"),
            response_content_type: a("RESPONSE_CONTENT_TYPE"),
            response_headers_names: s("RESPONSE_HEADERS_NAMES"),
            args_combined_size: a("ARGS_COMBINED_SIZE"),
            auth_type: a("AUTH_TYPE"),
            files_combined_size: a("FILES_COMBINED_SIZE"),
            full_request: a("FULL_REQUEST"),
            full_request_length: a("FULL_REQUEST_LENGTH"),
            inbound_data_error: a("INBOUND_DATA_ERROR"),
            matched_var: a("MATCHED_VAR"),
            matched_var_name: a("MATCHED_VAR_NAME"),
            msc_pcre_error: a("MSC_PCRE_ERROR"),
            msc_pcre_limits_exceeded: a("MSC_PCRE_LIMITS_EXCEEDED"),
            multipart_boundary_quoted: a("MULTIPART_BOUNDARY_QUOTED"),
            multipart_boundary_white_space: a("MULTIPART_BOUNDARY_WHITESPACE"),
            multipart_crlf_lf_lines: a("MULTIPART_CRLF_LF_LINES"),
            multipart_data_after: a("MULTIPART_DATA_AFTER"),
            multipart_data_before: a("MULTIPART_DATA_BEFORE"),
            multipart_duplicate_part_header: a("MULTIPART_DUPLICATE_PART_HEADER"),
            multipart_file_limit_exceeded: a("MULTIPART_FILE_LIMIT_EXCEEDED"),
            multipart_header_folding: a("MULTIPART_HEADER_FOLDING"),
            multipart_invalid_header_folding: a("MULTIPART_INVALID_HEADER_FOLDING"),
            multipart_invalid_part: a("MULTIPART_INVALID_PART"),
            multipart_invalid_quoting: a("MULTIPART_INVALID_QUOTING"),
            multipart_lf_line: a("MULTIPART_LF_LINE"),
            multipart_missing_semicolon: a("MULTIPART_MISSING_SEMICOLON"),
            multipart_strict_error: a("MULTIPART_STRICT_ERROR"),
            multipart_unmatched_boundary: a("MULTIPART_UNMATCHED_BOUNDARY"),
            outbound_data_error: a("OUTBOUND_DATA_ERROR"),
            path_info: a("PATH_INFO"),
            query_string: a("QUERY_STRING"),
            remote_addr: a("REMOTE_ADDR"),
            remote_host: a("REMOTE_HOST"),
            remote_port: a("REMOTE_PORT"),
            reqbody_error: a("REQBODY_ERROR"),
            reqbody_error_msg: a("REQBODY_ERROR_MSG"),
            reqbody_processor_error: a("REQBODY_PROCESSOR_ERROR"),
            reqbody_processor_error_msg: a("REQBODY_PROCESSOR_ERROR_MSG"),
            reqbody_processor: a("REQBODY_PROCESSOR"),
            request_basename: a("REQUEST_BASENAME"),
            request_body: a("REQUEST_BODY"),
            request_body_length: a("REQUEST_BODY_LENGTH"),
            request_filename: a("REQUEST_FILENAME"),
            request_line: a("REQUEST_LINE"),
            request_method: a("REQUEST_METHOD"),
            request_protocol: a("REQUEST_PROTOCOL"),
            request_uri: a("REQUEST_URI"),
            request_uri_raw: a("REQUEST_URI_RAW"),
            resource: a("RESOURCE"),
            response_body: a("RESPONSE_BODY"),
            response_content_length: a("RESPONSE_CONTENT_LENGTH"),
            response_protocol: a("RESPONSE_PROTOCOL"),
            response_status: a("RESPONSE_STATUS"),
            server_addr: a("SERVER_ADDR"),
            server_name: a("SERVER_NAME"),
            server_port: a("SERVER_PORT"),
            session_id: a("SESSIONID"),
            unique_id: a("UNIQUE_ID"),
            url_encoded_error: a("URLENCODED_ERROR"),
            user_id: a("USERID"),
            args: AnchoredSetVariable::with_names("ARGS", "ARGS_NAMES"),
            args_get: AnchoredSetVariable::with_names("ARGS_GET", "ARGS_GET_NAMES"),
            args_post: AnchoredSetVariable::with_names("ARGS_POST", "ARGS_POST_NAMES"),
            files_sizes: s("FILES_SIZES"),
            files_names: s("FILES_NAMES"),
            files_tmp_content: s("FILES_TMP_CONTENT"),
            multipart_file_name: s("MULTIPART_FILENAME"),
            multipart_file_name_charset: s("MULTIPART_FILENAME_CHARSET"),
            multipart_file_name_language: s("MULTIPART_FILENAME_LANGUAGE"),
            multipart_name: s("MULTIPART_NAME"),
            matched_vars_names: s("MATCHED_VARS_NAMES"),
            matched_vars: s("MATCHED_VARS"),
            files: s("FILES"),
            request_cookies: s("REQUEST_COOKIES"),
            request_headers: s("REQUEST_HEADERS"),
            response_headers: s("RESPONSE_HEADERS"),
            geo: s("GEO"),
            request_cookies_names: s("REQUEST_COOKIES_NAMES"),
            files_tmp_names: s("FILES_TMPNAMES"),
            multipart_part_headers: s("MULTIPART_PART_HEADERS"),
            offset: 0,
            args_names: AnchoredSetVariableTranslationProxy::new("ARGS_NAMES"),
            args_get_names: AnchoredSetVariableTranslationProxy::new("ARGS_GET_NAMES"),
            args_post_names: AnchoredSetVariableTranslationProxy::new("ARGS_POST_NAMES"),
        }
    }
}

/// Buffers of `SecRule::evaluate`, kept in the transaction so
/// that evaluating a rule does not allocate them again.
#[derive(Default)]
pub struct EvalScratch<'a> {
    /// The rule's final list of variables.
    pub vars: Vec<&'a Variable>,
    /// The values of one variable.
    pub e: Vec<VariableValue>,
    /// The transformation results of one value.
    pub values: TransformationResults,
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
    pub(crate) request_body_type: RequestBodyType,
    pub(crate) request_body_processor: RequestBodyType,
    #[cfg(feature = "libxml2")]
    pub(crate) xml: Option<Box<Xml>>,
    pub(crate) json: Json,
    pub(crate) multipart_part_tmp_files: Vec<Arc<MultipartPartTmpFile>>,
}

/// The settings rules changed for this transaction with `ctl:` (`None`:
/// the rule set's value applies).
pub(crate) struct CtlOverrides {
    /// `ctl:ruleEngine`.
    pub(crate) rule_engine: Option<RuleEngine>,
    /// `ctl:requestBodyAccess`.
    pub(crate) request_body_access: Option<bool>,
    /// `ctl:parseXmlIntoArgs` (starts as the rule set's value).
    pub(crate) parse_xml_into_args: Option<ParseXmlIntoArgs>,
    /// `ctl:auditEngine`.
    pub(crate) audit_engine: Option<AuditLogStatus>,
    /// `ctl:auditLogParts` changes, in rule order.
    pub(crate) audit_log_modifier: Vec<(PartsChange, Parts)>,
    /// `ctl:ruleRemoveById`: ranges of ids (of one id for a single one).
    pub(crate) rule_remove_by_id: Vec<std::ops::RangeInclusive<crate::rule::Id>>,
    pub(crate) rule_remove_by_tag: Vec<String>,
    pub(crate) rule_remove_target_by_tag: Vec<(String, String)>,
    pub(crate) rule_remove_target_by_id: Vec<(crate::rule::Id, String)>,
}

/// Where rule evaluation is: skips, markers, `allow`, the chain being
/// evaluated, captures, and buffers reused from rule to rule.
pub(crate) struct EvalState<'a> {
    /// Rules still to be skipped because of a `skip` action.
    pub(crate) skip_next: usize,
    /// The `SecMarker` being skipped to (by `skipAfter`).
    pub(crate) marker: Option<String>,
    /// Set by a matching `allow` action, until the rules it covers are
    /// skipped.
    pub(crate) allow_type: Option<AllowType>,
    /// Chain ancestors of the rule being evaluated, innermost last (a
    /// rule has no pointer to its parent).
    pub(crate) chained_rule_parents: Vec<&'a Rule>,
    /// Matched strings, used by the `capture` action.
    pub(crate) matched: Vec<Vec<u8>>,
    /// Buffers reused by rule evaluation.
    pub(crate) scratch: EvalScratch<'a>,
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
    /// Set by the `severity` action (`HIGHEST_SEVERITY`).
    pub(crate) highest_severity_action: u8,
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
    pub(crate) vars: TransactionAnchoredVariables,
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
            vars: TransactionAnchoredVariables::new(),
            collections: Collections::new(
                ms.global_collection.as_ref(),
                ms.ip_collection.as_ref(),
                ms.session_collection.as_ref(),
                ms.user_collection.as_ref(),
                ms.resource_collection.as_ref(),
            ),
            variable_envs: BTreeMap::new(),
            body: BodyProcessing {
                request_body_type: RequestBodyType::UnknownFormat,
                request_body_processor: RequestBodyType::UnknownFormat,
                #[cfg(feature = "libxml2")]
                xml: Some(Box::new(Xml::new())),
                json: Json::new(),
                multipart_part_tmp_files: Vec::new(),
            },
            ctl: CtlOverrides {
                rule_engine: None,
                request_body_access: None,
                parse_xml_into_args: rules.properties.settings.sec_xml_parse_xml_into_args,
                audit_engine: None,
                audit_log_modifier: Vec::new(),
                rule_remove_by_id: Vec::new(),
                rule_remove_by_tag: Vec::new(),
                rule_remove_target_by_tag: Vec::new(),
                rule_remove_target_by_id: Vec::new(),
            },
            eval: EvalState {
                skip_next: 0,
                marker: None,
                allow_type: None,
                chained_rule_parents: Vec::new(),
                matched: Vec::new(),
                scratch: EvalScratch::default(),
            },
            outcome: Outcome {
                rules_messages: Vec::new(),
                intervention: PendingIntervention::default(),
                is_interrupted: false,
                highest_severity_action: 255,
            },
            log_cb_data,
        };
        t.vars.url_encoded_error.set(b"0", 0);
        t.vars.msc_pcre_error.set(b"0", 0);
        t.vars.msc_pcre_limits_exceeded.set(b"0", 0);
        crate::ms_dbg!(&t, 4, "Initializing transaction");
        t
    }

    // ------------------------------------------------------------------
    // SecMarker management
    // ------------------------------------------------------------------

    pub(crate) fn is_inside_a_marker(&self) -> bool {
        self.eval.marker.is_some()
    }

    pub(crate) fn current_marker(&self) -> Option<&str> {
        self.eval.marker.as_deref()
    }

    pub(crate) fn remove_marker(&mut self) {
        self.eval.marker = None;
    }

    pub(crate) fn add_marker(&mut self, name: &str) {
        self.eval.marker = Some(name.to_string());
    }

    // ------------------------------------------------------------------
    // Phases
    // ------------------------------------------------------------------

    fn evaluate_phase(&mut self, phase: Phases) {
        let rules = self.rules;
        rules.evaluate(phase, self);
    }

    /// [`Self::process_connection`] with socket addresses. IPv6 addresses
    /// are written without brackets (`::1`), as servers report them.
    pub fn process_connection_addrs(&mut self, client: std::net::SocketAddr, server: std::net::SocketAddr) {
        let (c, s) = (client.ip().to_string(), server.ip().to_string());
        self.process_connection(&c, client.port(), &s, server.port());
    }

    /// Records the client and server addresses and ports and runs the
    /// rules of the connection phase.
    pub fn process_connection(&mut self, client: &str, c_port: u16, server: &str, s_port: u16) {
        self.http.client_ip_address = client.to_string();
        self.http.server_ip_address = server.to_string();
        if self.http.request_host_name.is_empty() {
            self.http.request_host_name = server.to_string();
        }
        self.http.client_port = c_port;
        self.http.server_port = s_port;
        crate::ms_dbg!(self, 4, "Transaction context created.");
        crate::ms_dbg!(self, 4, "Starting phase CONNECTION. (SecRules 0)");

        let off = self.vars.offset;
        self.vars.remote_host.set(self.http.client_ip_address.as_bytes(), off);
        self.vars.unique_id.set(self.id.as_bytes(), off);
        self.vars.remote_addr.set(self.http.client_ip_address.as_bytes(), off);
        self.vars.server_addr.set(self.http.server_ip_address.as_bytes(), off);
        self.vars.server_port.set(self.http.server_port.to_string().as_bytes(), off);
        self.vars.remote_port.set(self.http.client_port.to_string().as_bytes(), off);
        self.evaluate_phase(Phases::Connection);
    }

    fn argument_writer(&mut self) -> ArgumentWriter<'_> {
        ArgumentWriter {
            vars: &mut self.vars,
            combined_size: &mut self.http.args_combined_size,
            rules: self.rules,
            id: &self.id,
            uri: &self.http.uri,
        }
    }

    /// Adds the arguments of a query string or URL-encoded form body
    /// (`origin` is `GET` or `POST`). Always returns `true`.
    pub(crate) fn extract_arguments(&mut self, origin: &str, buf: &[u8], offset: usize) -> bool {
        self.argument_writer().extract(origin, buf, offset);
        true
    }

    #[cfg_attr(not(feature = "libxml2"), allow(dead_code))] // Used by the XML body processor.
    /// Adds one argument to `ARGS` and to `ARGS_GET` or `ARGS_POST`
    /// according to `origin`. Returns `false` when `SecArgumentsLimit` was
    /// reached.
    pub(crate) fn add_argument(&mut self, origin: &str, key: &[u8], value: &[u8], offset: usize) -> bool {
        self.argument_writer().add(origin, key, value, offset)
    }

    /// Records the request line (URI, method, HTTP version) and fills the
    /// URI variables and the query string arguments. No rules run here.
    pub fn process_uri(&mut self, uri: &[u8], method: &[u8], http_version: &[u8]) {
        crate::ms_dbg!(self, 4, "Starting phase URI. (SecRules 0 + 1/2)");
        self.http.http_version = String::from_utf8_lossy(http_version).into_owned();
        self.http.uri = uri.to_vec();
        let mut uri_s: &[u8] = uri;

        // any uri-fragment that was received should only be retained in
        // `http.uri`, REQUEST_URI_RAW and REQUEST_LINE.
        if let Some(pos) = uri_s.iter().position(|&c| c == b'#') {
            uri_s = &uri_s[..pos];
        }

        let pos_raw_query = uri_s.iter().position(|&c| c == b'?');
        let path_info_raw = match pos_raw_query {
            None => uri_s,
            Some(p) => &uri_s[..p],
        };
        let path_info = uri_decode(path_info_raw);
        self.http.uri_decoded = uri_decode(uri_s);

        let off = self.vars.offset;
        self.vars.request_method.set(method, 0);

        let mut request_line = method.to_vec();
        request_line.push(b' ');
        request_line.extend_from_slice(uri);
        let mut rl = request_line.clone();
        rl.extend_from_slice(b" HTTP/");
        rl.extend_from_slice(http_version);
        self.vars.request_line.set(&rl, off);

        let mut proto = b"HTTP/".to_vec();
        proto.extend_from_slice(http_version);
        self.vars.request_protocol.set(&proto, off + request_line.len() + 1);

        self.http.uri_no_query_string_decoded = path_info.clone();

        if let Some(p) = pos_raw_query {
            let qry = uri_s[p + 1..].to_vec();
            self.vars.query_string.set(&qry, p + 1 + method.len() + 1);
        }

        let var_size = pos_raw_query.unwrap_or(uri_s.len());
        self.vars.path_info.set_with_len(&path_info, off + method.len() + 1, var_size);
        self.vars.request_filename.set_with_len(&path_info, off + method.len() + 1, var_size);

        if let Some(o) = path_info.iter().rposition(|&c| c == b'/' || c == b'\\')
            && path_info.len() > o + 1
        {
            let basename = path_info[o + 1..].to_vec();
            self.vars.request_basename.set(&basename, off + method.len() + 1 + o + 1);
        }
        self.vars.offset = self.vars.request_line.value().len();

        let mut parsed_uri = self.http.uri_decoded.clone();
        // The more popular case is without domain
        if !self.http.uri_decoded.is_empty() && self.http.uri_decoded[0] != b'/' {
            let d = &self.http.uri_decoded;
            // The position after the first `:`, 0 when there is none.
            let scheme = d.iter().position(|&c| c == b':').map(|p| p + 1).unwrap_or(0);
            // The position after the next `//`, 1 when there is none.
            let netloc = crate::utils::string::find_from(d, b"//", scheme).map(|p| p + 2).unwrap_or(1);
            if netloc == scheme + 2
                && let Some(path) = d.iter().skip(netloc).position(|&c| c == b'/').map(|p| p + netloc)
            {
                parsed_uri = d[path..].to_vec();
            }
        }
        self.vars.request_uri.set_with_len(&parsed_uri, method.len() + 1, uri_s.len());
        self.vars.request_uri_raw.set(uri, method.len() + 1);

        if !self.vars.query_string.value().is_empty() {
            let qs = self.vars.query_string.value().to_vec();
            let qo = self.vars.query_string.offset();
            self.extract_arguments("GET", &qs, qo);
        }

        self.vars.offset += 1;
    }

    /// Phase 1: runs the request headers rules.
    pub fn process_request_headers(&mut self) {
        crate::ms_dbg!(self, 4, "Starting phase REQUEST_HEADERS.  (SecRules 1)");
        if self.rule_engine_state() == Some(RuleEngine::Disabled) {
            crate::ms_dbg!(self, 4, "Rule engine disabled, returning...");
            return;
        }
        self.evaluate_phase(Phases::RequestHeaders);
    }

    /// Adds a request header (`REQUEST_HEADERS`, `AUTH_TYPE`).
    pub fn add_request_header(&mut self, key: &[u8], value: &[u8]) {
        let off = self.vars.offset;
        self.vars.request_headers_names.set(key, key, off);
        self.vars.offset = off + key.len() + 2;
        let off = self.vars.offset;
        self.vars.request_headers.set(key, value, off);

        let keyl = key.to_ascii_lowercase();
        if keyl == b"authorization" {
            let ty = split(value, b' ');
            self.vars.auth_type.set(&ty[0], off);
        }

        if keyl == b"cookie" {
            let mut local_offset = off;
            let mut cookies = ssplit(value, b';');
            if let Some(final_cookie_pair) = cookies.last_mut() {
                // Get rid of any optional whitespace after the cookie-string
                while final_cookie_pair.last().is_some_and(|&c| is_space(c)) {
                    final_cookie_pair.pop();
                }
            }
            for c in &cookies {
                // skip empty substring, eg "Cookie: ;;foo=bar"
                if c.is_empty() {
                    local_offset += 1;
                    continue;
                }
                let (mut ckey, cval) = match c.iter().position(|&x| x == b'=') {
                    None => (c.clone(), Vec::new()),
                    Some(p) => (c[..p].to_vec(), c[p + 1..].to_vec()),
                };
                // ltrim the key - following the modsec v2 way
                while !ckey.is_empty() && is_space(ckey[0]) {
                    ckey.remove(0);
                    local_offset += 1;
                }
                if ckey.is_empty() {
                    local_offset = local_offset + c.len() + 1;
                    continue;
                }
                self.vars.request_cookies_names.set(&ckey, &ckey, local_offset);
                local_offset = local_offset + ckey.len() + 1;
                self.vars.request_cookies.set(&ckey, &cval, local_offset);
                local_offset = local_offset + cval.len() + 1;
            }
        }

        if keyl == b"content-type" {
            let l = value.to_ascii_lowercase();
            if l.starts_with(b"multipart/form-data") {
                self.body.request_body_type = RequestBodyType::MultiPartRequestBody;
                self.vars.reqbody_processor.set(b"MULTIPART", off);
            }
            if l.starts_with(b"application/x-www-form-urlencoded") {
                self.body.request_body_type = RequestBodyType::WWWFormUrlEncoded;
                self.vars.reqbody_processor.set(b"URLENCODED", off);
            }
        }

        if keyl == b"host" {
            let host = split(value, b':');
            self.vars.server_name.set(&host[0], off);
        }
        self.vars.offset = off + value.len() + 1;
    }

    /// Phase 2: parses the request body with its body processor and runs
    /// the request body rules.
    pub fn process_request_body(&mut self) {
        crate::ms_dbg!(self, 4, "Starting phase REQUEST_BODY. (SecRules 2)");

        if self.rule_engine_state() == Some(RuleEngine::Disabled) {
            crate::ms_dbg!(self, 4, "Rule engine disabled, returning...");
            return;
        }

        if self.vars.inbound_data_error.value().is_empty() {
            self.vars.inbound_data_error.set(b"0", 0);
        }

        // The body is parsed even when the rules are not given it.
        self.parse_request_body();
        if !self.request_body_access() {
            return;
        }
        self.set_request_body_variables();

        self.evaluate_phase(Phases::RequestBody);
    }

    /// [`Self::append_request_body`] with the content of a file.
    ///
    /// With a `SecRequestBodyLimit`, at most one byte more than the limit is
    /// read: that byte tells [`Self::append_request_body`] that the body is
    /// over the limit, and the rest is cut off or rejected anyway.
    pub fn request_body_from_file(&mut self, path: &str) -> std::io::Result<bool> {
        use std::io::Read;
        let limit = self.rules.properties.settings.request_body_limit.unwrap_or(0);
        let read = || -> std::io::Result<(u64, Vec<u8>)> {
            let file = std::fs::File::open(path)?;
            let size = file.metadata()?.len();
            let max = if limit > 0 { limit.saturating_add(1) } else { u64::MAX };
            let mut s = Vec::with_capacity(usize::try_from(size.min(max)).unwrap_or(0));
            file.take(max).read_to_end(&mut s)?;
            Ok((size, s))
        };
        let (size, s) = read().inspect_err(|_| {
            crate::ms_dbg!(self, 3, "Failed to open request body at: {}", path);
        })?;
        crate::ms_dbg!(self, 9, "Adding request body: {} bytes. Limit set to: {}", size, limit);
        Ok(self.append_request_body(&s))
    }

    /// Adds `buf` to the request body, within `SecRequestBodyLimit`.
    /// Returns `false` when the body limit was hit and only a part was kept
    /// (`SecRequestBodyLimitAction ProcessPartial`); see
    /// `append_body` for the limit actions.
    pub fn append_request_body(&mut self, buf: &[u8]) -> bool {
        crate::ms_dbg!(
            self,
            9,
            "Appending request body: {} bytes. Limit set to: {}",
            buf.len(),
            self.rules.properties.settings.request_body_limit.unwrap_or(0)
        );
        self.append_body(BodyDirection::Request, buf)
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

    /// Phase 3: records the response status and protocol and runs the
    /// response headers rules.
    pub fn process_response_headers(&mut self, code: u16, proto: &str) {
        crate::ms_dbg!(self, 4, "Starting phase RESPONSE_HEADERS. (SecRules 3)");
        self.http.http_code_returned = code;
        let off = self.vars.offset;
        self.vars.response_status.set(code.to_string().as_bytes(), off);
        self.vars.response_protocol.set(proto.as_bytes(), off);

        if self.rule_engine_state() == Some(RuleEngine::Disabled) {
            crate::ms_dbg!(self, 4, "Rule engine disabled, returning...");
            return;
        }
        self.evaluate_phase(Phases::ResponseHeaders);
    }

    /// Adds a response header (`RESPONSE_HEADERS`,
    /// `RESPONSE_CONTENT_TYPE`).
    pub fn add_response_header(&mut self, key: &[u8], value: &[u8]) {
        let off = self.vars.offset;
        self.vars.response_headers_names.set(key, key, off);
        self.vars.response_headers.set(key, value, off);
        if key.eq_ignore_ascii_case(b"content-type") {
            // Removes the charset=...
            let val = split(value, b';');
            if let Some(v) = val.first() {
                self.vars.response_content_type.set(v, 0);
            }
        }
    }

    fn response_type_is_inspected(&self) -> bool {
        let bi = &self.rules.properties.response_body_type_to_be_inspected.value;
        let ct = String::from_utf8_lossy(&self.vars.response_content_type.value().to_ascii_lowercase()).into_owned();
        bi.contains(&ct)
    }

    /// Phase 4: runs the response body rules, when the response body is
    /// inspected.
    pub fn process_response_body(&mut self) {
        crate::ms_dbg!(self, 4, "Starting phase RESPONSE_BODY. (SecRules 4)");

        if self.rule_engine_state() == Some(RuleEngine::Disabled) {
            crate::ms_dbg!(self, 4, "Rule engine disabled, returning...");
            return;
        }

        let props = &self.rules.properties;
        if props.settings.sec_response_body_access != Some(true) {
            crate::ms_dbg!(
                self,
                4,
                "Response body is disabled, returning... {}",
                config_boolean_code(props.settings.sec_response_body_access)
            );
            return;
        }

        if !self.response_type_is_inspected() && props.response_body_type_to_be_inspected.set {
            crate::ms_dbg!(
                self,
                5,
                "Response Content-Type is {}. It is not marked to be inspected.",
                String::from_utf8_lossy(self.vars.response_content_type.value())
            );
            let mut valid = String::new();
            for i in props.response_body_type_to_be_inspected.value.iter() {
                valid.push_str(i);
                valid.push(' ');
            }
            crate::ms_dbg!(self, 8, "Content-Type(s) marked to be inspected: {}", valid);
            return;
        }
        if self.vars.outbound_data_error.value().is_empty() {
            let off = self.vars.offset;
            self.vars.outbound_data_error.set(b"0", off);
        }

        let off = self.vars.offset;
        self.vars.response_body.set(&self.http.response_body, off);
        self.vars.response_content_length.set(self.http.response_body.len().to_string().as_bytes(), off);
        self.evaluate_phase(Phases::ResponseBody);
    }

    /// Adds `buf` to the response body, within `SecResponseBodyLimit`,
    /// when its content type is inspected. Returns `false` when the body
    /// limit was hit and only a part was kept
    /// (`SecResponseBodyLimitAction ProcessPartial`); see
    /// `append_body` for the limit actions.
    pub fn append_response_body(&mut self, buf: &[u8]) -> bool {
        let props = &self.rules.properties;
        let bi = &props.response_body_type_to_be_inspected.value;
        if !self.response_type_is_inspected() && !bi.is_empty() {
            crate::ms_dbg!(
                self,
                4,
                "Not appending response body. Response Content-Type is {}. It is not marked to be inspected.",
                String::from_utf8_lossy(self.vars.response_content_type.value())
            );
            return true;
        }

        crate::ms_dbg!(
            self,
            9,
            "Appending response body: {} bytes. Limit set to: {}",
            buf.len() + self.http.response_body.len(),
            props.settings.response_body_limit.unwrap_or(0)
        );
        self.append_body(BodyDirection::Response, buf)
    }

    /// Whether the request body went past `SecRequestBodyLimit`: no more
    /// of it is kept for the rules.
    pub(crate) fn request_body_limit_reached(&self) -> bool {
        self.vars.inbound_data_error.value() == b"1"
    }

    /// Whether the response body went past `SecResponseBodyLimit`: no
    /// more of it is kept for the rules.
    pub(crate) fn response_body_limit_reached(&self) -> bool {
        self.vars.outbound_data_error.value() == b"1"
    }

    /// The response body kept so far.
    pub fn response_body(&self) -> &[u8] {
        &self.http.response_body
    }

    /// The length of the response body kept so far.
    pub fn response_body_length(&self) -> usize {
        self.http.response_body.len()
    }

    /// The length of the request body kept so far.
    pub fn request_body_length(&self) -> usize {
        self.http.request_body.len()
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

    /// Sets the response status (`RESPONSE_STATUS`).
    pub fn update_status_code(&mut self, code: u16) {
        self.http.http_code_returned = code;
        let off = self.vars.offset;
        self.vars.response_status.set(code.to_string().as_bytes(), off);
    }

    /// Sets the host name the logs report (ignored when empty).
    pub fn set_request_host_name(&mut self, hostname: &str) {
        if !hostname.is_empty() {
            self.http.request_host_name = hostname.to_string();
        }
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

    /// With `Reject` and an engine that only detects, the rules see the
    /// body up to the limit: what `On` would have rejected.
    #[test]
    fn detection_only_sees_the_body_up_to_the_limit() {
        assert_eq!(run_body_limits("DetectionOnly", b"abcdefghij", b"vwxyz0123"), (vec![1, 2, 3, 4], false));
        assert_eq!(run_body_limits("On", b"abcdefghij", b"vwxyz0123"), (vec![2, 4], true));
        assert_eq!(run_body_limits("DetectionOnly", b"abcde", b"vwxyz"), (vec![1, 3], false));
    }
}
