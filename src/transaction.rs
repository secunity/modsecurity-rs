//! Port of `headers/modsecurity/transaction.h` and `src/transaction.cc`.
//!
//! A `Transaction` borrows its `ModSecurity` instance and `RulesSet` for its
//! whole life (`'a`), exactly as the C++ object keeps raw pointers to them
//! (the connector guarantees they outlive the transaction). The rule
//! messages it accumulates borrow the rules for the same lifetime.
//!
//! The C++ class inherits `TransactionAnchoredVariables` and
//! `TransactionSecMarkerManagement`; here the anchored variables are the
//! [`TransactionAnchoredVariables`] in the `vars` field (C++
//! `m_variableArgs` is `t.vars.args`) and the marker state is the `marker`
//! field.

use std::any::Any;
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::actions::disruptive::allow::AllowType;
use crate::anchored_set_variable::AnchoredSetVariable;
use crate::anchored_set_variable_translation_proxy::AnchoredSetVariableTranslationProxy;
use crate::anchored_variable::AnchoredVariable;
use crate::audit_log::{self, AuditLogStatus, PartsChange};
use crate::collection::collections::Collections;
use crate::intervention::Intervention;
use crate::modsecurity::{ModSecurity, Phases};
use crate::request_body_processor::json::Json;
use crate::request_body_processor::multipart::{Multipart, MultipartPartTmpFile};
#[cfg(feature = "libxml2")]
use crate::request_body_processor::xml::Xml;
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::{RuleWithActions, TransformationResults};
use crate::rules_set::RulesSet;
use crate::rules_set_properties::{
    BodyLimitAction, ParseXmlIntoArgs, RuleEngine, config_boolean_code, rule_engine_state_string,
};
use crate::unique_id::UniqueId;
use crate::utils::decode::{uri_decode, urldecode_nonstrict_inplace};
use crate::utils::json::JsonGen;
use crate::utils::string::{
    asc_time, dash_if_empty, double_to_string, is_space, split, ssplit, ssplit_pair, to_hex_if_needed, tolower,
};
use crate::variable_value::VariableValue;
use crate::variables::variable::Variable;

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

/// `TransactionAnchoredVariables`: the request/response variables filled
/// while the transaction is processed.
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

/// Buffers of `RuleWithOperator::evaluate`, kept in the transaction so
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

pub struct Transaction<'a> {
    /// CPU time at creation, base of the `DURATION` variable.
    pub creation_time_stamp: f64,
    pub client_ip_address: String,
    /// The HTTP version: 1.1, 2.0, ...
    pub http_version: String,
    pub server_ip_address: String,
    pub request_host_name: String,
    /// The raw URI that was requested.
    pub uri: Vec<u8>,
    /// The decoded URI without the query string.
    pub uri_no_query_string_decoded: Vec<u8>,
    /// Combined size of all arguments (`ARGS_COMBINED_SIZE`).
    pub args_combined_size_double: f64,
    pub client_port: i32,
    /// Set by the `severity` action (`HIGHEST_SEVERITY`).
    pub highest_severity_action: i32,
    /// The HTTP status code, when known.
    pub http_code_returned: i32,
    pub server_port: i32,
    pub ms: &'a ModSecurity,
    pub request_body_type: RequestBodyType,
    pub request_body_processor: RequestBodyType,
    pub rules: &'a RulesSet,
    pub rule_remove_by_id: Vec<i32>,
    pub rule_remove_by_id_range: Vec<(i32, i32)>,
    pub rule_remove_by_tag: Vec<String>,
    pub rule_remove_target_by_tag: Vec<(String, String)>,
    pub rule_remove_target_by_id: Vec<(i32, String)>,
    pub request_body_access: Option<bool>,
    /// `ctl:auditLogParts` modifications: (0 = add / 1 = remove, parts).
    /// `ctl:auditLogParts` changes for this transaction, in rule order.
    pub audit_log_modifier: Vec<(PartsChange, String)>,
    /// This transaction's most recent `ctl:auditEngine`.
    /// `ctl:auditEngine`, when a rule set it for this transaction.
    pub ctl_audit_engine: Option<AuditLogStatus>,
    /// Messages saved by `log`/`msg`/... for the audit log.
    pub rules_messages: Vec<RuleMessage<'a>>,
    pub request_body: Vec<u8>,
    pub response_body: Vec<u8>,
    /// The unique ID of the transaction (`UNIQUE_ID`).
    pub id: String,
    /// Rules still to be skipped because of a `skip` action.
    pub skip_next: i32,
    /// Set by a matching `allow` action, until the rules it covers are
    /// skipped.
    pub allow_type: Option<AllowType>,
    /// The decoded URI (raw is `uri`).
    pub uri_decoded: Vec<u8>,
    /// The pending disruptive action, handed out by
    /// [`Transaction::intervention`].
    pub(crate) intervention: Intervention,
    /// Sticky flag set the first time a disruptive intervention is consumed
    /// through [`Transaction::intervention`].
    pub is_interrupted: bool,
    /// Creation time (`std::time`).
    pub time_stamp: i64,
    pub collections: Collections<'a>,
    /// Matched strings, used by the `capture` action.
    pub matched: Vec<Vec<u8>>,
    #[cfg(feature = "libxml2")]
    pub xml: Option<Box<Xml>>,
    pub json: Option<Box<Json>>,
    pub sec_rule_engine: Option<RuleEngine>,
    pub sec_xml_parse_xml_into_args: Option<ParseXmlIntoArgs>,
    /// Environment variables set by `setenv`.
    pub variable_envs: BTreeMap<Vec<u8>, Vec<u8>>,
    pub multipart_part_tmp_files: Vec<Arc<MultipartPartTmpFile>>,
    pub vars: TransactionAnchoredVariables,
    /// `TransactionSecMarkerManagement`: the marker being skipped to.
    pub marker: Option<String>,
    /// Chain ancestors of the rule being evaluated (replaces the C++
    /// `RuleWithActions::m_chainedRuleParent` back pointers).
    pub chained_rule_parents: Vec<&'a RuleWithActions>,
    /// Buffers reused by rule evaluation.
    pub eval_scratch: EvalScratch<'a>,
    log_cb_data: Option<Box<dyn Any + Send>>,
}

fn transaction_id(id: Option<&str>, timestamp: i64) -> String {
    match id {
        Some(id) => id.to_string(),
        None => format!("{}{}", timestamp, double_to_string(crate::utils::random::generate_transaction_unique_id())),
    }
}

impl<'a> Transaction<'a> {
    /// `Transaction(ms, rules, logCbData)`
    pub fn new(ms: &'a ModSecurity, rules: &'a RulesSet, log_cb_data: Option<Box<dyn Any + Send>>) -> Self {
        Self::with_id_and_time(ms, rules, None, log_cb_data, crate::utils::system::now())
    }

    /// `Transaction(ms, rules, id, logCbData)`
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
            creation_time_stamp: crate::utils::system::cpu_seconds(),
            client_ip_address: String::new(),
            http_version: String::new(),
            server_ip_address: String::new(),
            request_host_name: String::new(),
            uri: Vec::new(),
            uri_no_query_string_decoded: Vec::new(),
            args_combined_size_double: 0.0,
            client_port: 0,
            highest_severity_action: 255,
            http_code_returned: 200,
            server_port: 0,
            ms,
            request_body_type: RequestBodyType::UnknownFormat,
            request_body_processor: RequestBodyType::UnknownFormat,
            rules,
            rule_remove_by_id: Vec::new(),
            rule_remove_by_id_range: Vec::new(),
            rule_remove_by_tag: Vec::new(),
            rule_remove_target_by_tag: Vec::new(),
            rule_remove_target_by_id: Vec::new(),
            request_body_access: None,
            audit_log_modifier: Vec::new(),
            ctl_audit_engine: None,
            rules_messages: Vec::new(),
            request_body: Vec::new(),
            response_body: Vec::new(),
            id: transaction_id(id, timestamp),
            skip_next: 0,
            allow_type: None,
            uri_decoded: Vec::new(),
            intervention: Intervention::default(),
            is_interrupted: false,
            time_stamp: timestamp,
            matched: Vec::new(),
            collections: Collections::new(
                ms.global_collection.as_ref(),
                ms.ip_collection.as_ref(),
                ms.session_collection.as_ref(),
                ms.user_collection.as_ref(),
                ms.resource_collection.as_ref(),
            ),
            #[cfg(feature = "libxml2")]
            xml: Some(Box::new(Xml::new())),
            json: Some(Box::new(Json::new())),
            sec_rule_engine: None,
            sec_xml_parse_xml_into_args: rules.properties.sec_xml_parse_xml_into_args,
            variable_envs: BTreeMap::new(),
            multipart_part_tmp_files: Vec::new(),
            vars: TransactionAnchoredVariables::new(),
            marker: None,
            chained_rule_parents: Vec::new(),
            eval_scratch: EvalScratch::default(),
            log_cb_data,
        };
        t.vars.url_encoded_error.set(b"0", 0);
        t.vars.msc_pcre_error.set(b"0", 0);
        t.vars.msc_pcre_limits_exceeded.set(b"0", 0);
        crate::ms_dbg_a!(&t, 4, "Initializing transaction");
        t
    }

    // ------------------------------------------------------------------
    // Debug log
    // ------------------------------------------------------------------

    /// Whether a debug message of `level` would be written (the test done by
    /// the `ms_dbg` macros).
    pub fn debug_enabled(&self, level: i32) -> bool {
        self.rules.properties.debug_log.enabled(level)
    }

    /// `debug(level, message)`
    pub fn debug(&self, level: i32, message: &str) {
        self.rules.debug(level, &self.id, &String::from_utf8_lossy(&self.uri), message);
    }

    // ------------------------------------------------------------------
    // SecMarker management
    // ------------------------------------------------------------------

    pub fn is_inside_a_marker(&self) -> bool {
        self.marker.is_some()
    }

    pub fn current_marker(&self) -> Option<&str> {
        self.marker.as_deref()
    }

    pub fn remove_marker(&mut self) {
        self.marker = None;
    }

    pub fn add_marker(&mut self, name: &str) {
        self.marker = Some(name.to_string());
    }

    // ------------------------------------------------------------------
    // Phases
    // ------------------------------------------------------------------

    fn evaluate_phase(&mut self, phase: Phases) {
        let rules = self.rules;
        rules.evaluate(phase, self);
    }

    /// `processConnection`
    pub fn process_connection(&mut self, client: &str, c_port: i32, server: &str, s_port: i32) {
        self.client_ip_address = client.to_string();
        self.server_ip_address = server.to_string();
        if self.request_host_name.is_empty() {
            self.request_host_name = server.to_string();
        }
        self.client_port = c_port;
        self.server_port = s_port;
        crate::ms_dbg_a!(self, 4, "Transaction context created.");
        crate::ms_dbg_a!(self, 4, "Starting phase CONNECTION. (SecRules 0)");

        let off = self.vars.offset;
        self.vars.remote_host.set(self.client_ip_address.as_bytes(), off);
        self.vars.unique_id.set(self.id.as_bytes(), off);
        self.vars.remote_addr.set(self.client_ip_address.as_bytes(), off);
        self.vars.server_addr.set(self.server_ip_address.as_bytes(), off);
        self.vars.server_port.set(self.server_port.to_string().as_bytes(), off);
        self.vars.remote_port.set(self.client_port.to_string().as_bytes(), off);
        self.evaluate_phase(Phases::Connection);
    }

    /// `extractArguments`
    pub fn extract_arguments(&mut self, orig: &str, buf: &[u8], mut offset: usize) -> bool {
        let sep1 = match &self.rules.properties.sec_argument_separator {
            Some(sep) => sep.as_bytes().first().copied().unwrap_or(b'&'),
            None => b'&',
        };
        for t in ssplit(buf, sep1) {
            let (mut key, mut value) = ssplit_pair(&t, b'=');
            let mut invalid_count = 0;
            urldecode_nonstrict_inplace(&mut key, &mut invalid_count);
            urldecode_nonstrict_inplace(&mut value, &mut invalid_count);
            if invalid_count > 0 {
                let off = self.vars.offset;
                self.vars.url_encoded_error.set(b"1", off);
            }
            self.add_argument(orig, &key, &value, offset);
            offset = offset + t.len() + 1;
        }
        true
    }

    /// `addArgument`
    pub fn add_argument(&mut self, orig: &str, key: &[u8], value: &[u8], mut offset: usize) -> bool {
        crate::ms_dbg_a!(
            self,
            4,
            "Adding request argument ({}): name \"{}\", value \"{}\"",
            orig,
            String::from_utf8_lossy(key),
            String::from_utf8_lossy(value)
        );
        if let Some(limit) = self.rules.properties.arguments_limit
            && self.vars.args.len() >= limit as usize
        {
            crate::ms_dbg_a!(self, 4, "Skipping request argument, over limit ({})", limit);
            return false;
        }
        offset = offset + key.len() + 1;
        self.vars.args.set(key, value, offset);
        if orig == "GET" {
            self.vars.args_get.set(key, value, offset);
        } else if orig == "POST" {
            self.vars.args_post.set(key, value, offset);
        }
        self.args_combined_size_double += (key.len() + value.len()) as f64;
        let s = double_to_string(self.args_combined_size_double);
        self.vars.args_combined_size.set_with_len(s.as_bytes(), offset - key.len() - 1, key.len());
        self.vars.args_combined_size.set_with_len(s.as_bytes(), offset, value.len());
        true
    }

    /// `processURI`
    pub fn process_uri(&mut self, uri: &[u8], method: &[u8], http_version: &[u8]) {
        crate::ms_dbg_a!(self, 4, "Starting phase URI. (SecRules 0 + 1/2)");
        self.http_version = String::from_utf8_lossy(http_version).into_owned();
        self.uri = uri.to_vec();
        let mut uri_s: &[u8] = uri;

        // any uri-fragment that was received should only be retained in
        // m_uri, REQUEST_URI_RAW and REQUEST_LINE.
        if let Some(pos) = uri_s.iter().position(|&c| c == b'#') {
            uri_s = &uri_s[..pos];
        }

        let pos_raw_query = uri_s.iter().position(|&c| c == b'?');
        let path_info_raw = match pos_raw_query {
            None => uri_s,
            Some(p) => &uri_s[..p],
        };
        let path_info = uri_decode(path_info_raw);
        self.uri_decoded = uri_decode(uri_s);

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

        self.uri_no_query_string_decoded = path_info.clone();

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
        self.vars.offset = self.vars.request_line.value.len();

        let mut parsed_uri = self.uri_decoded.clone();
        // The more popular case is without domain
        if !self.uri_decoded.is_empty() && self.uri_decoded[0] != b'/' {
            let d = &self.uri_decoded;
            // `find(":") + 1`: npos + 1 wraps to 0 in C++.
            let scheme = d.iter().position(|&c| c == b':').map(|p| p + 1).unwrap_or(0);
            // `find("//", scheme) + 2`; npos + 2 wraps to 1.
            let netloc = crate::utils::string::find_from(d, b"//", scheme).map(|p| p + 2).unwrap_or(1);
            if netloc == scheme + 2
                && let Some(path) = d.iter().skip(netloc).position(|&c| c == b'/').map(|p| p + netloc)
            {
                parsed_uri = d[path..].to_vec();
            }
        }
        self.vars.request_uri.set_with_len(&parsed_uri, method.len() + 1, uri_s.len());
        self.vars.request_uri_raw.set(uri, method.len() + 1);

        if !self.vars.query_string.value.is_empty() {
            let qs = self.vars.query_string.value.clone();
            let qo = self.vars.query_string.offset;
            self.extract_arguments("GET", &qs, qo);
        }

        self.vars.offset += 1;
    }

    /// `processRequestHeaders`
    pub fn process_request_headers(&mut self) {
        crate::ms_dbg_a!(self, 4, "Starting phase REQUEST_HEADERS.  (SecRules 1)");
        if self.rule_engine_state() == Some(RuleEngine::Disabled) {
            crate::ms_dbg_a!(self, 4, "Rule engine disabled, returning...");
            return;
        }
        self.evaluate_phase(Phases::RequestHeaders);
    }

    /// `addRequestHeader`
    pub fn add_request_header(&mut self, key: &[u8], value: &[u8]) {
        let off = self.vars.offset;
        self.vars.request_headers_names.set(key, key, off);
        self.vars.offset = off + key.len() + 2;
        let off = self.vars.offset;
        self.vars.request_headers.set(key, value, off);

        let keyl = tolower(key);
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
            let l = tolower(value);
            if l.starts_with(b"multipart/form-data") {
                self.request_body_type = RequestBodyType::MultiPartRequestBody;
                self.vars.reqbody_processor.set(b"MULTIPART", off);
            }
            if l.starts_with(b"application/x-www-form-urlencoded") {
                self.request_body_type = RequestBodyType::WWWFormUrlEncoded;
                self.vars.reqbody_processor.set(b"URLENCODED", off);
            }
        }

        if keyl == b"host" {
            let host = split(value, b':');
            self.vars.server_name.set(&host[0], off);
        }
        self.vars.offset = off + value.len() + 1;
    }

    /// `processRequestBody`
    pub fn process_request_body(&mut self) {
        crate::ms_dbg_a!(self, 4, "Starting phase REQUEST_BODY. (SecRules 2)");

        if self.rule_engine_state() == Some(RuleEngine::Disabled) {
            crate::ms_dbg_a!(self, 4, "Rule engine disabled, returning...");
            return;
        }

        if self.vars.inbound_data_error.value.is_empty() {
            self.vars.inbound_data_error.set(b"0", 0);
        }

        // Process the request body even if there is nothing to be done.
        let a = self.vars.request_headers.resolve_first(b"Content-Type");
        let props = &self.rules.properties;

        let mut request_body_no_files_limit_exceeded = false;
        if (self.request_body_type == RequestBodyType::WWWFormUrlEncoded
            || self.request_body_processor == RequestBodyType::JSONRequestBody
            || self.request_body_processor == RequestBodyType::XMLRequestBody)
            && let Some(limit) = props.request_body_no_files_limit
            && self.request_body.len() as u64 > limit
        {
            self.vars.reqbody_error.set(b"1", 0);
            self.vars.reqbody_error_msg.set(b"Request body excluding files is bigger than the maximum expected.", 0);
            let off = self.vars.offset;
            self.vars.inbound_data_error.set(b"1", off);
            crate::ms_dbg_a!(
                self,
                5,
                "Request body excluding files is bigger than the maximum expected. Limit: {}",
                limit
            );
            request_body_no_files_limit_exceeded = true;
        }

        let body = self.request_body.clone();
        let set_error = |t: &mut Self, prefix: &str, error: &str, both_msgs: bool| {
            let off = t.vars.offset;
            let msg = format!("{}{}", prefix, error);
            t.vars.reqbody_error.set(b"1", off);
            t.vars.reqbody_processor_error.set(b"1", off);
            t.vars.reqbody_error_msg.set(msg.as_bytes(), off);
            if both_msgs {
                t.vars.reqbody_processor_error_msg.set(msg.as_bytes(), off);
            }
        };
        let set_ok = |t: &mut Self| {
            let off = t.vars.offset;
            t.vars.reqbody_error.set(b"0", off);
            t.vars.reqbody_processor_error.set(b"0", off);
        };

        #[allow(unused_mut)]
        let mut handled = false;
        #[cfg(feature = "libxml2")]
        if self.request_body_processor == RequestBodyType::XMLRequestBody {
            handled = true;
            // large size might cause issues in the parsing itself; omit if
            // exceeded
            if !request_body_no_files_limit_exceeded {
                let mut xml = self.xml.take().unwrap_or_else(|| Box::new(Xml::new()));
                let mut error = None;
                if xml.init(self) {
                    // The error of `complete` replaces that of `process_chunk`.
                    error = xml.process_chunk(self, &body).err();
                    error = xml.complete(self).err().or(error);
                }
                self.xml = Some(xml);
                if let Some(error) = error {
                    set_error(self, "XML parsing error: ", &error, true);
                } else {
                    set_ok(self);
                }
            }
        }
        if handled {
            // done
        } else if self.request_body_processor == RequestBodyType::JSONRequestBody {
            if !request_body_no_files_limit_exceeded {
                let mut json = self.json.take().unwrap_or_else(|| Box::new(Json::new()));
                if let Some(depth) = self.rules.properties.request_body_json_depth_limit {
                    json.set_max_depth(depth);
                }
                json.process_chunk(&body);
                let result = json.complete(self);
                self.json = Some(json);
                if let Err(error) = result
                    && !body.is_empty()
                {
                    set_error(self, "JSON parsing error: ", &error, true);
                } else {
                    set_ok(self);
                }
            }
        } else if self.request_body_type == RequestBodyType::MultiPartRequestBody {
            let mut error = None;
            let mut reqbody_no_files_length: u64 = 0;
            if let Some(a) = &a {
                let mut m = Multipart::new(a);
                if m.init(self) {
                    let off = self.vars.offset;
                    m.process(self, &body, off);
                }
                reqbody_no_files_length = m.reqbody_no_files_length as u64;
                m.multipart_complete(self);
                error = m.error().map(str::to_owned);
            }
            let limit = self.rules.properties.request_body_no_files_limit;
            if let Some(error) = error {
                set_error(self, "Multipart parsing error: ", &error, true);
            } else if let Some(limit) = limit
                && reqbody_no_files_length > limit
            {
                self.vars.reqbody_error.set(b"1", 0);
                self.vars
                    .reqbody_error_msg
                    .set(b"Request body excluding files is bigger than the maximum expected.", 0);
                let off = self.vars.offset;
                self.vars.inbound_data_error.set(b"1", off);
                crate::ms_dbg_a!(
                    self,
                    5,
                    "Request body excluding files is bigger than the maximum expected. Limit: {}",
                    limit
                );
            } else {
                set_ok(self);
            }
        } else if self.request_body_type == RequestBodyType::WWWFormUrlEncoded {
            self.vars.offset += 1;
            if !request_body_no_files_limit_exceeded {
                let off = self.vars.offset;
                self.extract_arguments("POST", &body, off);
            }
        } else if self.request_body_type != RequestBodyType::UnknownFormat {
            let error = a.as_ref().map(|a| String::from_utf8_lossy(a).into_owned()).unwrap_or_default();
            set_error(self, "Unknown request body processor: ", &error, true);
        } else {
            set_ok(self);
        }

        let props = &self.rules.properties;
        if props.sec_request_body_access == Some(false) {
            if self.request_body_access != Some(true) {
                crate::ms_dbg_a!(self, 4, "Request body processing is disabled");
                return;
            } else {
                crate::ms_dbg_a!(
                    self,
                    4,
                    "Request body processing is disabled, but enabled to this transaction due to ctl:requestBodyAccess action"
                );
            }
        } else if self.request_body_access == Some(false) {
            crate::ms_dbg_a!(
                self,
                4,
                "Request body processing is enabled, but disabled to this transaction due to ctl:requestBodyAccess action"
            );
            return;
        }

        // FULL_REQUEST
        let mut full_request: Vec<u8> = Vec::new();
        let mut l: Vec<VariableValue> = Vec::new();
        self.vars.request_headers.resolve(&mut l);
        for h in &l {
            full_request.extend_from_slice(h.key());
            full_request.extend_from_slice(b": ");
            full_request.extend_from_slice(h.value());
            full_request.push(b'\n');
        }
        full_request.extend_from_slice(b"\n\n");
        full_request.extend_from_slice(&self.request_body);
        let off = self.vars.offset;
        self.vars.full_request.set(&full_request, off);
        self.vars.full_request_length.set(full_request.len().to_string().as_bytes(), off);

        if !self.request_body.is_empty() {
            let rb = self.request_body.clone();
            self.vars.request_body.set(&rb, off);
            self.vars.request_body_length.set_with_len(rb.len().to_string().as_bytes(), off, rb.len());
        }

        self.evaluate_phase(Phases::RequestBody);
    }

    /// `requestBodyFromFile`: [`Self::append_request_body`] with the
    /// content of a file.
    pub fn request_body_from_file(&mut self, path: &str) -> std::io::Result<bool> {
        let s = std::fs::read(path).inspect_err(|_| {
            crate::ms_dbg_a!(self, 3, "Failed to open request body at: {}", path);
        })?;
        crate::ms_dbg_a!(
            self,
            9,
            "Adding request body: {} bytes. Limit set to: {}",
            s.len(),
            self.rules.properties.request_body_limit.unwrap_or(0)
        );
        Ok(self.append_request_body(&s))
    }

    /// `appendRequestBody`: adds `buf` to the request body. Returns `false`
    /// when the body limit was hit and only a part was kept
    /// (`SecRequestBodyLimitAction ProcessPartial`).
    pub fn append_request_body(&mut self, buf: &[u8]) -> bool {
        let current_size = self.request_body.len();
        let props = &self.rules.properties;
        crate::ms_dbg_a!(
            self,
            9,
            "Appending request body: {} bytes. Limit set to: {}",
            buf.len(),
            props.request_body_limit.unwrap_or(0)
        );

        if props.request_body_limit.unwrap_or(0) > 0
            && props.request_body_limit.unwrap_or(0) < (buf.len() + current_size) as u64
        {
            let off = self.vars.offset;
            self.vars.inbound_data_error.set(b"1", off);
            crate::ms_dbg_a!(self, 5, "Request body is bigger than the maximum expected.");
            if props.request_body_limit_action == Some(BodyLimitAction::ProcessPartial) {
                let space_left = (props.request_body_limit.unwrap_or(0) as usize).saturating_sub(current_size);
                let n = space_left.min(buf.len());
                self.request_body.extend_from_slice(&buf[..n]);
                crate::ms_dbg_a!(self, 5, "Request body limit is marked to process partial");
                return false;
            } else {
                if props.request_body_limit_action == Some(BodyLimitAction::Reject) {
                    crate::ms_dbg_a!(self, 5, "Request body limit is marked to reject the request");
                    if self.rule_engine_state() == Some(RuleEngine::Enabled) {
                        self.intervention = Intervention {
                            status: 403,
                            url: None,
                            log: Some("Request body limit is marked to reject the request".into()),
                            disruptive: true,
                        };
                    } else {
                        crate::ms_dbg_a!(self, 5, "Not rejecting the request as the engine is not Enabled");
                    }
                }
                return true;
            }
        }
        self.request_body.extend_from_slice(buf);
        true
    }

    /// `processResponseHeaders`
    pub fn process_response_headers(&mut self, code: i32, proto: &str) {
        crate::ms_dbg_a!(self, 4, "Starting phase RESPONSE_HEADERS. (SecRules 3)");
        self.http_code_returned = code;
        let off = self.vars.offset;
        self.vars.response_status.set(code.to_string().as_bytes(), off);
        self.vars.response_protocol.set(proto.as_bytes(), off);

        if self.rule_engine_state() == Some(RuleEngine::Disabled) {
            crate::ms_dbg_a!(self, 4, "Rule engine disabled, returning...");
            return;
        }
        self.evaluate_phase(Phases::ResponseHeaders);
    }

    /// `addResponseHeader`
    pub fn add_response_header(&mut self, key: &[u8], value: &[u8]) {
        let off = self.vars.offset;
        self.vars.response_headers_names.set(key, key, off);
        self.vars.response_headers.set(key, value, off);
        if tolower(key) == b"content-type" {
            // Removes the charset=...
            let val = split(value, b';');
            if let Some(v) = val.first() {
                self.vars.response_content_type.set(v, 0);
            }
        }
    }

    fn response_type_is_inspected(&self) -> bool {
        let bi = &self.rules.properties.response_body_type_to_be_inspected.value;
        let ct = String::from_utf8_lossy(&tolower(&self.vars.response_content_type.value)).into_owned();
        bi.contains(&ct)
    }

    /// `processResponseBody`
    pub fn process_response_body(&mut self) {
        crate::ms_dbg_a!(self, 4, "Starting phase RESPONSE_BODY. (SecRules 4)");

        if self.rule_engine_state() == Some(RuleEngine::Disabled) {
            crate::ms_dbg_a!(self, 4, "Rule engine disabled, returning...");
            return;
        }

        let props = &self.rules.properties;
        if props.sec_response_body_access != Some(true) {
            crate::ms_dbg_a!(
                self,
                4,
                "Response body is disabled, returning... {}",
                config_boolean_code(props.sec_response_body_access)
            );
            return;
        }

        if !self.response_type_is_inspected() && props.response_body_type_to_be_inspected.set {
            crate::ms_dbg_a!(
                self,
                5,
                "Response Content-Type is {}. It is not marked to be inspected.",
                String::from_utf8_lossy(&self.vars.response_content_type.value)
            );
            let mut valid = String::new();
            for i in props.response_body_type_to_be_inspected.value.iter() {
                valid.push_str(i);
                valid.push(' ');
            }
            crate::ms_dbg_a!(self, 8, "Content-Type(s) marked to be inspected: {}", valid);
            return;
        }
        if self.vars.outbound_data_error.value.is_empty() {
            let off = self.vars.offset;
            self.vars.outbound_data_error.set(b"0", off);
        }

        let off = self.vars.offset;
        let rb = self.response_body.clone();
        self.vars.response_body.set(&rb, off);
        self.vars.response_content_length.set(rb.len().to_string().as_bytes(), off);
        self.evaluate_phase(Phases::ResponseBody);
    }

    /// `appendResponseBody`: adds `buf` to the response body. Returns
    /// `false` when the body limit was hit and only a part was kept
    /// (`SecResponseBodyLimitAction ProcessPartial`).
    pub fn append_response_body(&mut self, buf: &[u8]) -> bool {
        let current_size = self.response_body.len();
        let props = &self.rules.properties;
        let bi = &props.response_body_type_to_be_inspected.value;
        if !self.response_type_is_inspected() && !bi.is_empty() {
            crate::ms_dbg_a!(
                self,
                4,
                "Not appending response body. Response Content-Type is {}. It is not marked to be inspected.",
                String::from_utf8_lossy(&self.vars.response_content_type.value)
            );
            return true;
        }

        crate::ms_dbg_a!(
            self,
            9,
            "Appending response body: {} bytes. Limit set to: {}",
            buf.len() + current_size,
            props.response_body_limit.unwrap_or(0)
        );

        if props.response_body_limit.unwrap_or(0) > 0
            && props.response_body_limit.unwrap_or(0) < (buf.len() + current_size) as u64
        {
            let off = self.vars.offset;
            self.vars.outbound_data_error.set(b"1", off);
            crate::ms_dbg_a!(self, 5, "Response body is bigger than the maximum expected.");
            if props.response_body_limit_action == Some(BodyLimitAction::ProcessPartial) {
                let space_left = (props.response_body_limit.unwrap_or(0) as usize).saturating_sub(current_size);
                let n = space_left.min(buf.len());
                self.response_body.extend_from_slice(&buf[..n]);
                crate::ms_dbg_a!(self, 5, "Response body limit is marked to process partial");
                return false;
            } else {
                if props.response_body_limit_action == Some(BodyLimitAction::Reject) {
                    crate::ms_dbg_a!(self, 5, "Response body limit is marked to reject the request");
                    if self.rule_engine_state() == Some(RuleEngine::Enabled) {
                        self.intervention = Intervention {
                            status: 403,
                            url: None,
                            log: Some("Response body limit is marked to reject the request".into()),
                            disruptive: true,
                        };
                    } else {
                        crate::ms_dbg_a!(self, 5, "Not rejecting the request as the engine is not Enabled");
                    }
                }
                return true;
            }
        }
        self.response_body.extend_from_slice(buf);
        true
    }

    /// `getResponseBody`
    pub fn response_body(&self) -> &[u8] {
        &self.response_body
    }

    /// `getResponseBodyLength`
    pub fn response_body_length(&self) -> usize {
        self.response_body.len()
    }

    /// `getRequestBodyLength`
    pub fn request_body_length(&self) -> usize {
        self.request_body.len()
    }

    /// `processLogging`
    pub fn process_logging(&mut self) {
        crate::ms_dbg_a!(self, 4, "Starting phase LOGGING. (SecRules 5)");

        if self.rule_engine_state() == Some(RuleEngine::Disabled) {
            crate::ms_dbg_a!(self, 4, "Rule engine disabled, returning...");
            return;
        }

        self.evaluate_phase(Phases::Logging);

        // If relevant, save this transaction information at the audit_logs
        let audit = &self.rules.properties.audit_log;
        let mut parts = audit.parts();
        crate::ms_dbg_a!(self, 8, "Checking if this request is suitable to be saved as an audit log.");

        if !self.audit_log_modifier.is_empty() {
            crate::ms_dbg_a!(self, 4, "There was an audit log modifier for this transaction.");
            crate::ms_dbg_a!(self, 7, "AuditLog parts before modification(s): {}.", parts);
            for (op, p) in &self.audit_log_modifier {
                parts = match op {
                    PartsChange::Add => audit_log::AuditLog::add_parts(parts, p),
                    PartsChange::Remove => audit_log::AuditLog::remove_parts(parts, p),
                };
            }
        }
        crate::ms_dbg_a!(self, 8, "Checking if this request is relevant to be part of the audit logs.");
        let saved = audit.save_if_relevant(self, Some(parts));
        if saved {
            crate::ms_dbg_a!(self, 8, "Request was relevant to be saved. Parts: {}", parts);
        }
    }

    /// `intervention`: the pending disruptive intervention, if any, with
    /// `%d` in its log replaced by the status code. Handing it out resets
    /// the status and the disruptive flag (the url and log stay, as in C++).
    pub fn intervention(&mut self) -> Option<Intervention> {
        if !self.intervention.disruptive {
            return None;
        }
        self.is_interrupted = true;
        let mut it = self.intervention.clone();
        if let Some(log) = &mut it.log {
            *log = log.replace("%d", &it.status.to_string());
        }
        self.intervention.reset();
        Some(it)
    }

    /// `toOldAuditLogFormatIndex`
    pub fn to_old_audit_log_format_index(&self, filename: &str, size: f64, md5: &str) -> Vec<u8> {
        let tstr = crate::utils::system::strftime_local(self.time_stamp, "[%d/%b/%Y:%H:%M:%S %z]");
        let mut ss: Vec<u8> = Vec::new();
        let rh = &self.vars.request_headers;
        ss.extend_from_slice(&dash_if_empty(rh.resolve_first(b"Host").as_deref()));
        ss.push(b' ');
        ss.extend_from_slice(&dash_if_empty(Some(self.client_ip_address.as_bytes())));
        ss.push(b' ');
        let remote_user = crate::variables::computed::remote_user_name(self);
        ss.extend_from_slice(&dash_if_empty(Some(&remote_user)));
        ss.push(b' ');
        ss.extend_from_slice(tstr.as_bytes());
        ss.push(b' ');
        ss.push(b'"');
        ss.extend_from_slice(&dash_if_empty(Some(self.vars.request_method.evaluate())));
        ss.push(b' ');
        ss.extend_from_slice(cstr_prefix(&self.uri));
        ss.push(b' ');
        ss.extend_from_slice(b"HTTP/");
        ss.extend_from_slice(self.http_version.as_bytes());
        ss.extend_from_slice(b"\" ");
        ss.extend_from_slice(format!("{} {} ", self.http_code_returned, self.response_body.len()).as_bytes());
        ss.extend_from_slice(&dash_if_empty(rh.resolve_first(b"REFERER").as_deref()));
        ss.push(b' ');
        ss.push(b'"');
        ss.extend_from_slice(&dash_if_empty(rh.resolve_first(b"User-Agent").as_deref()));
        ss.extend_from_slice(b"\" ");
        ss.extend_from_slice(self.id.as_bytes());
        ss.push(b' ');
        ss.extend_from_slice(&dash_if_empty(rh.resolve_first(b"REFERER").as_deref()));
        ss.push(b' ');
        ss.extend_from_slice(filename.as_bytes());
        ss.push(b' ');
        ss.extend_from_slice(b"0 ");
        ss.extend_from_slice(double_to_string(size).as_bytes());
        ss.push(b' ');
        ss.extend_from_slice(b"md5:");
        ss.extend_from_slice(md5.as_bytes());
        ss.push(b'\n');
        ss
    }

    /// `toOldAuditLogFormat`
    pub fn to_old_audit_log_format(&self, parts: i32, trailer: &str, prefix: &str) -> Vec<u8> {
        use audit_log::AuditLog as AL;
        let tstr = crate::utils::system::strftime_local(self.time_stamp, "[%d/%b/%Y:%H:%M:%S %z]");
        let p = prefix.as_bytes();
        let mut a: Vec<u8> = Vec::new();
        let line = |a: &mut Vec<u8>, s: &[u8]| {
            a.extend_from_slice(s);
            a.push(b'\n');
        };
        let section = |a: &mut Vec<u8>, letter: &str| {
            a.extend_from_slice(p);
            a.extend_from_slice(format!("--{}-{}--\n", trailer, letter).as_bytes());
        };
        section(&mut a, "A");
        a.extend_from_slice(p);
        a.extend_from_slice(tstr.as_bytes());
        a.extend_from_slice(
            format!(
                " {} {} {} {} {}\n",
                self.id, self.client_ip_address, self.client_port, self.server_ip_address, self.server_port
            )
            .as_bytes(),
        );

        if parts & AL::B_AUDIT_LOG_PART != 0 {
            section(&mut a, "B");
            a.extend_from_slice(p);
            a.extend_from_slice(&dash_if_empty(Some(self.vars.request_method.evaluate())));
            a.push(b' ');
            a.extend_from_slice(cstr_prefix(&self.uri));
            a.extend_from_slice(b" HTTP/");
            line(&mut a, self.http_version.as_bytes());
            let mut l = Vec::new();
            self.vars.request_headers.resolve(&mut l);
            for h in &l {
                let pos = "REQUEST_HEADERS:".len();
                a.extend_from_slice(p);
                a.extend_from_slice(cstr_prefix(&h.key_with_collection()[pos.min(h.key_with_collection().len())..]));
                a.extend_from_slice(b": ");
                line(&mut a, cstr_prefix(h.value()));
            }
            line(&mut a, p);
        }
        if parts & AL::C_AUDIT_LOG_PART != 0 && !self.request_body.is_empty() {
            section(&mut a, "C");
            a.extend_from_slice(p);
            line(&mut a, &self.request_body);
            line(&mut a, p);
        }
        if parts & AL::D_AUDIT_LOG_PART != 0 {
            section(&mut a, "D");
            line(&mut a, p);
            // TODO (C++): write audit_log D part.
        }
        if parts & AL::E_AUDIT_LOG_PART != 0 && !self.response_body.is_empty() {
            let body = to_hex_if_needed(&self.response_body, false);
            section(&mut a, "E");
            if !body.is_empty() {
                a.extend_from_slice(p);
                line(&mut a, body.as_bytes());
            }
            line(&mut a, p);
        }
        if parts & AL::F_AUDIT_LOG_PART != 0 {
            section(&mut a, "F");
            a.extend_from_slice(p);
            line(&mut a, format!("HTTP/{} {}", self.http_version, self.http_code_returned).as_bytes());
            let mut l = Vec::new();
            self.vars.response_headers.resolve(&mut l);
            for h in &l {
                a.extend_from_slice(p);
                a.extend_from_slice(cstr_prefix(h.key()));
                a.extend_from_slice(b": ");
                line(&mut a, cstr_prefix(h.value()));
            }
        }
        line(&mut a, p);
        if parts & AL::G_AUDIT_LOG_PART != 0 {
            section(&mut a, "G");
            a.push(b'\n');
            // TODO (C++): write audit_log G part.
        }
        if parts & AL::H_AUDIT_LOG_PART != 0 {
            section(&mut a, "H");
            for m in &self.rules_messages {
                a.extend_from_slice(p);
                line(&mut a, m.log(self, 0, self.http_code_returned).as_bytes());
            }
            line(&mut a, p);
        }
        if parts & AL::I_AUDIT_LOG_PART != 0 {
            section(&mut a, "I");
            line(&mut a, p);
        }
        if parts & AL::J_AUDIT_LOG_PART != 0 {
            section(&mut a, "J");
            line(&mut a, p);
        }
        if parts & AL::K_AUDIT_LOG_PART != 0 {
            section(&mut a, "K");
            line(&mut a, p);
        }
        section(&mut a, "Z");
        a.push(b'\n');
        a
    }

    /// `toJSON`
    pub fn to_json(&self, parts: i32) -> Vec<u8> {
        use audit_log::AuditLog as AL;
        let ts = asc_time(self.time_stamp);
        let unique_id = UniqueId::unique_id();
        let mut g = JsonGen::new();

        g.map_open();
        g.string(b"transaction");
        g.map_open();

        // Part: A (header mandatory)
        g.add("client_ip", self.client_ip_address.as_bytes());
        g.add("time_stamp", ts.as_bytes());
        g.add("server_id", unique_id.as_bytes());
        g.add_num("client_port", self.client_port as i64);
        g.add("host_ip", self.server_ip_address.as_bytes());
        g.add_num("host_port", self.server_port as i64);
        g.add("unique_id", self.id.as_bytes());
        g.string(b"is_interrupted");
        g.bool(self.is_interrupted);

        // request
        g.string(b"request");
        g.map_open();
        g.add("method", &dash_if_empty(Some(self.vars.request_method.evaluate())));
        g.add("http_version", self.http_version.as_bytes());
        g.add("hostname", self.request_host_name.as_bytes());
        g.add("uri", &self.uri);
        if parts & AL::C_AUDIT_LOG_PART != 0 {
            // FIXME (C++): check for the binary content size.
            g.add("body", to_hex_if_needed(&self.request_body, false).as_bytes());
        }
        if parts & AL::B_AUDIT_LOG_PART != 0 {
            g.string(b"headers");
            g.map_open();
            let mut l = Vec::new();
            self.vars.request_headers.resolve(&mut l);
            for h in &l {
                g.string(to_hex_if_needed(cstr_prefix(h.key()), false).as_bytes());
                g.string(to_hex_if_needed(h.value(), false).as_bytes());
            }
            g.map_close();
        }
        g.map_close();

        // response
        g.string(b"response");
        g.map_open();
        if parts & AL::E_AUDIT_LOG_PART != 0 {
            g.add("body", &self.response_body);
        }
        g.add_num("http_code", self.http_code_returned as i64);
        if parts & AL::F_AUDIT_LOG_PART != 0 {
            g.string(b"headers");
            g.map_open();
            let mut l = Vec::new();
            self.vars.response_headers.resolve(&mut l);
            for h in &l {
                g.string(cstr_prefix(h.key()));
                g.string(h.value());
            }
            g.map_close();
        }
        g.map_close();

        // producer
        if parts & AL::H_AUDIT_LOG_PART != 0 {
            g.string(b"producer");
            g.map_open();
            g.add("modsecurity", self.ms.who_am_i().as_bytes());
            g.add("connector", self.ms.connector_information().as_bytes());
            g.add("secrules_engine", rule_engine_state_string(self.rule_engine_state()).as_bytes());
            g.string(b"components");
            g.array_open();
            for a in &self.rules.properties.components {
                g.string(a.as_bytes());
            }
            g.array_close();
            g.map_close();

            // messages
            g.string(b"messages");
            g.array_open();
            for a in &self.rules_messages {
                g.map_open();
                g.add("message", &a.message);
                g.string(b"details");
                g.map_open();
                g.add("match", &a.match_);
                g.add("reference", &a.reference);
                g.add("ruleId", a.rule.rule_id.to_string().as_bytes());
                g.add("file", a.rule.file_name.as_bytes());
                g.add("lineNumber", a.rule.line_number.to_string().as_bytes());
                g.add("data", to_hex_if_needed(&a.data, false).as_bytes());
                g.add("severity", a.severity.to_string().as_bytes());
                g.add("ver", a.rule.ver.as_bytes());
                g.add("rev", a.rule.rev.as_bytes());
                g.string(b"tags");
                g.array_open();
                for b in &a.tags {
                    g.string(b);
                }
                g.array_close();
                g.add("maturity", a.rule.maturity.to_string().as_bytes());
                g.add("accuracy", a.rule.accuracy.to_string().as_bytes());
                g.map_close();
                g.map_close();
            }
            g.array_close();
        }

        g.map_close();
        g.map_close();
        let mut log = g.into_buf();
        log.push(b'\n');
        log
    }

    /// `serverLog`
    pub fn server_log(&self, rm: &RuleMessage<'_>) {
        self.ms.server_log(self.log_cb_data.as_deref(), rm, self);
    }

    /// `getRuleEngineState`: this transaction's `ctl:ruleEngine`, else
    /// `SecRuleEngine`.
    pub fn rule_engine_state(&self) -> Option<RuleEngine> {
        self.sec_rule_engine.or(self.rules.properties.sec_rule_engine)
    }

    /// `updateStatusCode`
    pub fn update_status_code(&mut self, code: i32) {
        self.http_code_returned = code;
        let off = self.vars.offset;
        self.vars.response_status.set(code.to_string().as_bytes(), off);
    }

    /// `setRequestHostName`
    pub fn set_request_host_name(&mut self, hostname: &str) {
        if !hostname.is_empty() {
            self.request_host_name = hostname.to_string();
        }
    }

    /// The callback data given at construction.
    pub fn log_cb_data(&self) -> Option<&(dyn Any + Send)> {
        self.log_cb_data.as_deref()
    }
}

impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        // C++ `~MultipartPartTmpFile` (run when the transaction releases its
        // temp files) logs while deleting; do it here while the transaction
        // (and its debug log) is still alive.
        let me: &Transaction<'_> = self;
        for f in &me.multipart_part_tmp_files {
            f.release(Some(me));
        }
    }
}

/// The C++ code often writes `std::string::c_str()` into streams, which
/// stops at the first NUL byte.
fn cstr_prefix(s: &[u8]) -> &[u8] {
    match s.iter().position(|&c| c == 0) {
        Some(p) => &s[..p],
        None => s,
    }
}

/// The libmodsecurity C API for transactions (`msc_new_transaction`, ...).
pub mod c_api {
    use super::Transaction;
    use crate::intervention::{self, ModSecurityIntervention};
    use crate::modsecurity::ModSecurity;
    use crate::modsecurity::c_api::CLogData;
    use crate::rules_set::RulesSet;
    use std::ffi::{CStr, c_char, c_int, c_uchar, c_void};

    /// The C API hands out transactions without a lifetime; the connector
    /// guarantees the `ModSecurity` and `RulesSet` outlive them.
    pub type CTransaction = Transaction<'static>;

    unsafe fn bytes<'a>(p: *const c_char) -> &'a [u8] {
        if p.is_null() {
            return b"";
        }
        // SAFETY: C API contract: NUL terminated strings.
        unsafe { CStr::from_ptr(p) }.to_bytes()
    }

    unsafe fn slice<'a>(p: *const c_uchar, len: usize) -> &'a [u8] {
        if p.is_null() || len == 0 {
            return b"";
        }
        // SAFETY: C API contract: `p` points to `len` readable bytes.
        unsafe { std::slice::from_raw_parts(p, len) }
    }

    /// # Safety
    /// `ms` and `rules` must be valid and outlive the transaction.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn msc_new_transaction(
        ms: *mut ModSecurity,
        rules: *mut RulesSet,
        log_cb_data: *mut c_void,
    ) -> *mut CTransaction {
        // SAFETY: see the function contract.
        let (ms, rules): (&'static ModSecurity, &'static RulesSet) = unsafe { (&*ms, &*rules) };
        Box::into_raw(Box::new(Transaction::new(ms, rules, Some(Box::new(CLogData(log_cb_data))))))
    }

    /// # Safety
    /// As [`msc_new_transaction`]; `id` is a C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn msc_new_transaction_with_id(
        ms: *mut ModSecurity,
        rules: *mut RulesSet,
        id: *const c_char,
        log_cb_data: *mut c_void,
    ) -> *mut CTransaction {
        // SAFETY: see the function contract.
        let (ms, rules): (&'static ModSecurity, &'static RulesSet) = unsafe { (&*ms, &*rules) };
        let id = String::from_utf8_lossy(unsafe { bytes(id) }).into_owned();
        Box::into_raw(Box::new(Transaction::with_id(ms, rules, &id, Some(Box::new(CLogData(log_cb_data))))))
    }

    macro_rules! tx {
        ($t:expr) => {
            // SAFETY: the C API contract: a live transaction pointer.
            match unsafe { $t.as_mut() } {
                Some(t) => t,
                None => return 0,
            }
        };
    }

    /// # Safety
    /// `t` must come from `msc_new_transaction*`; strings are C strings.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn msc_process_connection(
        t: *mut CTransaction,
        client: *const c_char,
        c_port: c_int,
        server: *const c_char,
        s_port: c_int,
    ) -> c_int {
        let t = tx!(t);
        let c = String::from_utf8_lossy(unsafe { bytes(client) }).into_owned();
        let s = String::from_utf8_lossy(unsafe { bytes(server) }).into_owned();
        t.process_connection(&c, c_port, &s, s_port);
        1
    }

    /// # Safety
    /// As above.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn msc_process_uri(
        t: *mut CTransaction,
        uri: *const c_char,
        protocol: *const c_char,
        http_version: *const c_char,
    ) -> c_int {
        let t = tx!(t);
        t.process_uri(unsafe { bytes(uri) }, unsafe { bytes(protocol) }, unsafe { bytes(http_version) });
        1
    }

    /// # Safety
    /// As above.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn msc_process_request_headers(t: *mut CTransaction) -> c_int {
        tx!(t).process_request_headers();
        1
    }

    /// # Safety
    /// As above.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn msc_process_request_body(t: *mut CTransaction) -> c_int {
        tx!(t).process_request_body();
        1
    }

    /// # Safety
    /// As above; `buf` points to `len` bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn msc_append_request_body(t: *mut CTransaction, buf: *const c_uchar, len: usize) -> c_int {
        c_int::from(tx!(t).append_request_body(unsafe { slice(buf, len) }))
    }

    /// # Safety
    /// As above.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn msc_request_body_from_file(t: *mut CTransaction, path: *const c_char) -> c_int {
        let t = tx!(t);
        let p = String::from_utf8_lossy(unsafe { bytes(path) }).into_owned();
        // 0 when the file cannot be read, as in C++.
        t.request_body_from_file(&p).map_or(0, c_int::from)
    }

    /// # Safety
    /// As above.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn msc_process_response_headers(
        t: *mut CTransaction,
        code: c_int,
        protocol: *const c_char,
    ) -> c_int {
        let t = tx!(t);
        let p = String::from_utf8_lossy(unsafe { bytes(protocol) }).into_owned();
        t.process_response_headers(code, &p);
        1
    }

    /// # Safety
    /// As above.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn msc_process_response_body(t: *mut CTransaction) -> c_int {
        tx!(t).process_response_body();
        1
    }

    /// # Safety
    /// As above; `buf` points to `len` bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn msc_append_response_body(t: *mut CTransaction, buf: *const c_uchar, len: usize) -> c_int {
        c_int::from(tx!(t).append_response_body(unsafe { slice(buf, len) }))
    }

    /// # Safety
    /// As above; `key`/`value` are C strings.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn msc_add_request_header(
        t: *mut CTransaction,
        key: *const c_uchar,
        value: *const c_uchar,
    ) -> c_int {
        let t = tx!(t);
        t.add_request_header(unsafe { bytes(key as *const c_char) }, unsafe { bytes(value as *const c_char) });
        1
    }

    /// # Safety
    /// As above; `key`/`value` point to `len_*` bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn msc_add_n_request_header(
        t: *mut CTransaction,
        key: *const c_uchar,
        len_key: usize,
        value: *const c_uchar,
        len_value: usize,
    ) -> c_int {
        let t = tx!(t);
        t.add_request_header(unsafe { slice(key, len_key) }, unsafe { slice(value, len_value) });
        1
    }

    /// # Safety
    /// As above; `key`/`value` are C strings.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn msc_add_response_header(
        t: *mut CTransaction,
        key: *const c_uchar,
        value: *const c_uchar,
    ) -> c_int {
        let t = tx!(t);
        t.add_response_header(unsafe { bytes(key as *const c_char) }, unsafe { bytes(value as *const c_char) });
        1
    }

    /// # Safety
    /// As above; `key`/`value` point to `len_*` bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn msc_add_n_response_header(
        t: *mut CTransaction,
        key: *const c_uchar,
        len_key: usize,
        value: *const c_uchar,
        len_value: usize,
    ) -> c_int {
        let t = tx!(t);
        t.add_response_header(unsafe { slice(key, len_key) }, unsafe { slice(value, len_value) });
        1
    }

    /// # Safety
    /// `t` must come from `msc_new_transaction*` and not be used after.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn msc_transaction_cleanup(t: *mut CTransaction) {
        if !t.is_null() {
            drop(unsafe { Box::from_raw(t) });
        }
    }

    /// # Safety
    /// `t` as above; `it` points to a valid intervention struct.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn msc_intervention(t: *mut CTransaction, it: *mut ModSecurityIntervention) -> c_int {
        let t = tx!(t);
        // SAFETY: valid out-pointer per contract.
        let Some(it) = (unsafe { it.as_mut() }) else {
            return 0;
        };
        if let Some(pending) = t.intervention() {
            it.fill_from(&pending);
        }
        // C++ returns the caller's field (filled above when there was one).
        it.disruptive
    }

    /// # Safety
    /// `it` points to an intervention filled by `msc_intervention`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn msc_intervention_cleanup(it: *mut ModSecurityIntervention) {
        if let Some(it) = unsafe { it.as_mut() } {
            it.free_and_clean();
        }
    }

    /// # Safety
    /// `t` as above. The returned string is `malloc`ed (free with `free`).
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn msc_get_response_body(t: *const CTransaction) -> *const c_char {
        // SAFETY: live transaction per contract.
        let Some(t) = (unsafe { t.as_ref() }) else {
            return std::ptr::null();
        };
        // strdup(m_responseBody.str().c_str()): the raw bytes up to the
        // first NUL byte.
        intervention::strdup(t.response_body())
    }

    /// # Safety
    /// `t` as above.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn msc_get_response_body_length(t: *mut CTransaction) -> usize {
        tx!(t).response_body_length()
    }

    /// # Safety
    /// `t` as above.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn msc_get_request_body_length(t: *mut CTransaction) -> usize {
        tx!(t).request_body_length()
    }

    /// # Safety
    /// `t` as above.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn msc_process_logging(t: *mut CTransaction) -> c_int {
        tx!(t).process_logging();
        1
    }

    /// # Safety
    /// `t` as above.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn msc_update_status_code(t: *mut CTransaction, status: c_int) -> c_int {
        tx!(t).update_status_code(status);
        1
    }

    /// # Safety
    /// `t` as above; `hostname` is a C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn msc_set_request_hostname(t: *mut CTransaction, hostname: *const c_uchar) -> c_int {
        let t = tx!(t);
        let h = String::from_utf8_lossy(unsafe { bytes(hostname as *const c_char) }).into_owned();
        t.set_request_host_name(&h);
        1
    }

    /// # Safety
    /// `t` as above.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn msc_get_rules_messages_size(t: *const CTransaction) -> usize {
        // SAFETY: live transaction per contract.
        unsafe { t.as_ref() }.map(|t| t.rules_messages.len()).unwrap_or(0)
    }

    /// # Safety
    /// `t` as above; `ids` points to `ids_len` writable slots.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn msc_get_rules_messages_rule_ids(
        t: *const CTransaction,
        ids: *mut i64,
        ids_len: usize,
    ) -> usize {
        // SAFETY: live transaction per contract.
        let Some(t) = (unsafe { t.as_ref() }) else {
            return 0;
        };
        if ids.is_null() || ids_len == 0 {
            return 0;
        }
        let mut written = 0;
        for m in &t.rules_messages {
            if written >= ids_len {
                break;
            }
            // SAFETY: written < ids_len, within the caller's buffer.
            unsafe { *ids.add(written) = m.rule.rule_id };
            written += 1;
        }
        written
    }
}
