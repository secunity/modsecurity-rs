//! `variables` (mirrors `src/variables/`).
//!
//! One module per C++ header/source pair. The C++ `DEFINE_VARIABLE*`
//! macros are the `define_variable!` / `define_variable_dict!` macros of
//! [`variable`]; the hand written classes (collections, `RULE`, `ENV`,
//! `TIME*`, ...) live in their own modules. [`new_variable`] is the part of
//! the C++ grammar (`var:` in `seclang-parser.yy`) that builds them.

/// `DEFINE_VARIABLE_DICT(n, N, e)` for the `*_NAMES` variables whose
/// transaction member is an `AnchoredSetVariableTranslationProxy`
/// (`ARGS_NAMES`, `ARGS_GET_NAMES`, `ARGS_POST_NAMES`). In C++ the proxy
/// keeps a pointer to the set variable it translates (`$fount`); here that
/// source is passed in at resolution time. Generates the same module layout
/// as `define_variable_dict!`: `n::DictElement`, `n::NoDictElement` and
/// `n::DictElementRegexp`.
macro_rules! define_variable_dict_proxy {
    ($n:ident, $N:literal, $e:ident, $fount:ident) => {
        #[allow(non_snake_case)]
        pub mod $n {
            use $crate::rule_with_actions::RuleWithActions;
            use $crate::transaction::Transaction;
            use $crate::variable_value::VariableValue;
            use $crate::variables::variable::{Variable, VariableBase, VariableDictElement, VariableRegex};

            /// `<n>_DictElement`
            #[derive(Debug)]
            pub struct DictElement(pub VariableDictElement);

            impl DictElement {
                pub fn new(dict_element: &str) -> Self {
                    DictElement(VariableDictElement::new($N, dict_element))
                }
            }

            impl Variable for DictElement {
                fn base(&self) -> &VariableBase {
                    &self.0.base
                }
                fn base_mut(&mut self) -> &mut VariableBase {
                    &mut self.0.base
                }
                fn evaluate(&self, t: &Transaction<'_>, _rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
                    t.vars.$e.resolve_key(&t.vars.$fount, self.0.dict_element.as_bytes(), l);
                }
            }

            /// `<n>_NoDictElement`
            #[derive(Debug)]
            pub struct NoDictElement(pub VariableBase);

            impl NoDictElement {
                pub fn new() -> Self {
                    NoDictElement(VariableBase::new($N))
                }
            }

            impl Default for NoDictElement {
                fn default() -> Self {
                    Self::new()
                }
            }

            impl Variable for NoDictElement {
                fn base(&self) -> &VariableBase {
                    &self.0
                }
                fn base_mut(&mut self) -> &mut VariableBase {
                    &mut self.0
                }
                fn evaluate(&self, t: &Transaction<'_>, _rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
                    t.vars.$e.resolve_with_exclusions(&t.vars.$fount, l, &self.0.key_exclusion, Some(t));
                }
            }

            /// `<n>_DictElementRegexp`
            #[derive(Debug)]
            pub struct DictElementRegexp(pub VariableRegex);

            impl DictElementRegexp {
                pub fn new(regex: &str) -> Self {
                    DictElementRegexp(VariableRegex::new($N, regex))
                }
            }

            impl Variable for DictElementRegexp {
                fn base(&self) -> &VariableBase {
                    &self.0.base
                }
                fn base_mut(&mut self) -> &mut VariableBase {
                    &mut self.0.base
                }
                fn evaluate(&self, t: &Transaction<'_>, _rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
                    t.vars.$e.resolve_regular_expression_with_exclusions(
                        &t.vars.$fount,
                        &self.0.r,
                        l,
                        &self.0.base.key_exclusion,
                        Some(t),
                    );
                }
                fn regex(&self) -> Option<&$crate::utils::regex::Regex> {
                    Some(&self.0.r)
                }
            }
        }
    };
}

pub mod args;
pub mod args_combined_size;
pub mod args_get;
pub mod args_get_names;
pub mod args_names;
pub mod args_post;
pub mod args_post_names;
pub mod auth_type;
pub mod duration;
pub mod env;
pub mod files;
pub mod files_combined_size;
pub mod files_names;
pub mod files_sizes;
pub mod files_tmp_content;
pub mod files_tmp_names;
pub mod full_request;
pub mod full_request_length;
pub mod geo;
pub mod highest_severity;
pub mod inbound_data_error;
pub mod matched_var;
pub mod matched_var_name;
pub mod matched_vars;
pub mod matched_vars_names;
pub mod modsec_build;
pub mod msc_pcre_error;
pub mod msc_pcre_limits_exceeded;
pub mod multipart_boundary_quoted;
pub mod multipart_boundary_whitespace;
pub mod multipart_crlf_lf_lines;
pub mod multipart_data_after;
pub mod multipart_data_before;
pub mod multipart_duplicate_part_header;
pub mod multipart_file_limit_exceeded;
pub mod multipart_file_name;
pub mod multipart_file_name_charset;
pub mod multipart_file_name_language;
pub mod multipart_header_folding;
pub mod multipart_invalid_header_folding;
pub mod multipart_invalid_part;
pub mod multipart_invalid_quoting;
pub mod multipart_lf_line;
pub mod multipart_missing_semicolon;
pub mod multipart_name;
pub mod multipart_part_headers;
pub mod multipart_strict_error;
pub mod multipart_unmatched_boundary;
pub mod outbound_data_error;
pub mod path_info;
pub mod persistent;
pub mod query_string;
pub mod remote_addr;
pub mod remote_host;
pub mod remote_port;
pub mod remote_user;
pub mod reqbody_error;
pub mod reqbody_error_msg;
pub mod reqbody_processor;
pub mod reqbody_processor_error;
pub mod reqbody_processor_error_msg;
pub mod request_base_name;
pub mod request_body;
pub mod request_body_length;
pub mod request_cookies;
pub mod request_cookies_names;
pub mod request_file_name;
pub mod request_headers;
pub mod request_headers_names;
pub mod request_line;
pub mod request_method;
pub mod request_protocol;
pub mod request_uri;
pub mod request_uri_raw;
pub mod response_body;
pub mod response_content_length;
pub mod response_content_type;
pub mod response_headers;
pub mod response_headers_names;
pub mod response_protocol;
pub mod response_status;
pub mod rule;
pub mod server_addr;
pub mod server_name;
pub mod server_port;
pub mod session_id;
pub mod status;
pub mod time;
pub mod time_day;
pub mod time_epoch;
pub mod time_hour;
pub mod time_min;
pub mod time_mon;
pub mod time_sec;
pub mod time_wday;
pub mod time_year;
pub mod tx;
pub mod unique_id;
pub mod url_encoded_error;
pub mod user_id;
pub mod variable;
pub mod web_app_id;
pub mod xml;

/// How a variable is selected in a rule target: `ARGS`, `ARGS:foo`,
/// `ARGS:/regex/` or, for the collections that accept it, a key built from
/// macros (`TX:%{...}`, the C++ `*_DynamicElement` classes).
#[derive(Debug)]
pub enum VariableSelector {
    None,
    DictElement(String),
    Regexp(String),
    Dynamic(crate::run_time_string::RunTimeString),
}

/// Creates the variable for the scanner token `name` with the given
/// selector: the actions of the `var:` rule of the C++ grammar
/// (`seclang-parser.yy`). Returns `None` for unknown names and for
/// selectors the grammar does not accept for that variable (e.g.
/// `REQUEST_METHOD:foo`, `ARGS:%{...}`, `WEBSERVER_ERROR_LOG`), which are
/// syntax errors in C++. The `!` / `&` modifiers are applied by the caller.
///
/// `name` is matched case insensitively (the scanner's patterns are
/// `(?i:...)`). For the `RUN_TIME_VAR_*` tokens (`DURATION`, `MODSEC_BUILD`,
/// `HIGHEST_SEVERITY`, `REMOTE_USER`, `TIME*`) the C++ grammar names the
/// variable with the text as written in the rule (`yytext`), so `name` is
/// used verbatim for those.
///
/// | token(s) | `None` | `DictElement(e)` | `Regexp(r)` | `Dynamic(m)` |
/// |---|---|---|---|---|
/// | `ARGS`, `ARGS_GET`, `ARGS_POST`, `ARGS_NAMES`, `ARGS_GET_NAMES`, `ARGS_POST_NAMES`, `FILES`, `FILES_NAMES`, `FILES_SIZES`, `FILES_TMP_CONTENT`, `FILES_TMPNAMES`, `GEO`, `MATCHED_VARS`, `MATCHED_VARS_NAMES`, `MULTIPART_FILENAME`, `MULTIPART_FILENAME_CHARSET`, `MULTIPART_FILENAME_LANGUAGE`, `MULTIPART_NAME`, `MULTIPART_PART_HEADERS`, `REQUEST_COOKIES`, `REQUEST_COOKIES_NAMES`, `REQUEST_HEADERS`, `REQUEST_HEADERS_NAMES`, `RESPONSE_HEADERS`, `RESPONSE_HEADERS_NAMES` | `X::NoDictElement` | `X::DictElement` | `X::DictElementRegexp` | - |
/// | `RULE` | `RuleNoDictElement` | `RuleDictElement` | `RuleDictElementRegexp` | - |
/// | `TX`, `IP`, `GLOBAL`, `SESSION`, `USER`, `RESOURCE` | `XNoDictElement` | `XDictElement` | `XDictElementRegexp` | `XDynamicElement` |
/// | `ENV` | `Env("ENV")` | `Env("ENV:" + e)` | `Env("ENV:" + r)` | - |
/// | `XML` | `XmlNoDictElement` | `Xml("XML:" + e)` | `Xml("XML:" + r)` | - |
/// | `DURATION`, `MODSEC_BUILD`, `HIGHEST_SEVERITY`, `REMOTE_USER`, `TIME`, `TIME_DAY`, `TIME_EPOCH`, `TIME_HOUR`, `TIME_MIN`, `TIME_MON`, `TIME_SEC`, `TIME_WDAY`, `TIME_YEAR` | `X(name)` | - | - | - |
/// | `STATUS`, `STATUS_LINE` | `Status` | - | - | - |
/// | `MULTIPART_MISSING_SEMICOLON`, `MULTIPART_SEMICOLON_MISSING` | `MultipartMissingSemicolon` | - | - | - |
/// | `WEBAPPID` | `WebAppId` | - | - | - |
/// | every other single valued variable (`REQUEST_METHOD`, `UNIQUE_ID`, `SESSIONID`, `USERID`, `REQUEST_FILENAME`, ...) | its `define_variable!` type | - | - | - |
///
/// (The `ENV:/regex/` and `XML:/regex/` forms are not regular expressions
/// in C++ either: the text between the slashes is used as the key.)
pub fn new_variable(name: &str, selector: VariableSelector) -> Option<Box<dyn variable::Variable>> {
    use VariableSelector as S;
    use persistent::Persistent;
    use variable::Variable;

    /// The `DEFINE_VARIABLE_DICT` style variables (module `$m` with the
    /// three `DictElement` / `NoDictElement` / `DictElementRegexp` types).
    macro_rules! dict {
        ($m:path) => {{
            use $m as m;
            match selector {
                S::None => Some(Box::new(m::NoDictElement::new()) as Box<dyn Variable>),
                S::DictElement(e) => Some(Box::new(m::DictElement::new(&e)) as Box<dyn Variable>),
                S::Regexp(r) => Some(Box::new(m::DictElementRegexp::new(&r)) as Box<dyn Variable>),
                S::Dynamic(_) => None,
            }
        }};
    }
    /// The collections (`X_DictElement`, `X_NoDictElement`,
    /// `X_DictElementRegexp`, `X_DynamicElement`).
    macro_rules! collection {
        ($dict:path, $no:path, $re:path, $dyn:path) => {{
            match selector {
                S::None => Some(Box::new(<$no>::new()) as Box<dyn Variable>),
                S::DictElement(e) => Some(Box::new(<$dict>::new(&e)) as Box<dyn Variable>),
                S::Regexp(r) => Some(Box::new(<$re>::new(&r)) as Box<dyn Variable>),
                S::Dynamic(m) => Some(Box::new(<$dyn>::new(m)) as Box<dyn Variable>),
            }
        }};
    }
    /// The single valued variables: no selector accepted.
    macro_rules! single {
        ($e:expr) => {{
            match selector {
                S::None => Some(Box::new($e) as Box<dyn Variable>),
                _ => None,
            }
        }};
    }

    let token = name.to_ascii_uppercase();
    match token.as_str() {
        // DEFINE_VARIABLE_DICT
        "ARGS" => dict!(args::Args),
        "ARGS_POST" => dict!(args_post::ArgsPost),
        "ARGS_GET" => dict!(args_get::ArgsGet),
        "FILES_SIZES" => dict!(files_sizes::FilesSizes),
        "FILES_NAMES" => dict!(files_names::FilesNames),
        "FILES_TMP_CONTENT" => dict!(files_tmp_content::FilesTmpContent),
        "MULTIPART_FILENAME" => dict!(multipart_file_name::MultiPartFileName),
        "MULTIPART_FILENAME_CHARSET" => dict!(multipart_file_name_charset::MultiPartFileNameCharset),
        "MULTIPART_FILENAME_LANGUAGE" => dict!(multipart_file_name_language::MultiPartFileNameLanguage),
        "MULTIPART_NAME" => dict!(multipart_name::MultiPartName),
        "MATCHED_VARS_NAMES" => dict!(matched_vars_names::MatchedVarsNames),
        "MATCHED_VARS" => dict!(matched_vars::MatchedVars),
        "FILES" => dict!(files::Files),
        "REQUEST_COOKIES" => dict!(request_cookies::RequestCookies),
        "REQUEST_HEADERS" => dict!(request_headers::RequestHeaders),
        "RESPONSE_HEADERS" => dict!(response_headers::ResponseHeaders),
        "GEO" => dict!(geo::Geo),
        "REQUEST_COOKIES_NAMES" => dict!(request_cookies_names::RequestCookiesNames),
        "MULTIPART_PART_HEADERS" => dict!(multipart_part_headers::MultipartPartHeaders),
        "FILES_TMPNAMES" => dict!(files_tmp_names::FilesTmpNames),
        "ARGS_NAMES" => dict!(args_names::ArgsNames),
        "ARGS_GET_NAMES" => dict!(args_get_names::ArgsGetNames),
        "ARGS_POST_NAMES" => dict!(args_post_names::ArgsPostNames),
        "REQUEST_HEADERS_NAMES" => dict!(request_headers_names::RequestHeadersNames),
        "RESPONSE_HEADERS_NAMES" => dict!(response_headers_names::ResponseHeadersNames),

        "RULE" => match selector {
            S::None => Some(Box::new(rule::RuleNoDictElement::new())),
            S::DictElement(e) => Some(Box::new(rule::RuleDictElement::new(&e))),
            S::Regexp(r) => Some(Box::new(rule::RuleDictElementRegexp::new(&r))),
            S::Dynamic(_) => None,
        },

        // Collections
        "RESOURCE" => Some(Persistent::Resource.variable(selector)),
        "IP" => Some(Persistent::Ip.variable(selector)),
        "GLOBAL" => Some(Persistent::Global.variable(selector)),
        "USER" => Some(Persistent::User.variable(selector)),
        "TX" => collection!(tx::TxDictElement, tx::TxNoDictElement, tx::TxDictElementRegexp, tx::TxDynamicElement),
        "SESSION" => Some(Persistent::Session.variable(selector)),

        // RUN_TIME_VAR_ENV / RUN_TIME_VAR_XML
        "ENV" => match selector {
            S::None => Some(Box::new(env::Env::new("ENV"))),
            S::DictElement(e) | S::Regexp(e) => Some(Box::new(env::Env::new(&format!("ENV:{}", e)))),
            S::Dynamic(_) => None,
        },
        "XML" => match selector {
            S::None => Some(Box::new(xml::XmlNoDictElement::new())),
            S::DictElement(e) | S::Regexp(e) => Some(Box::new(xml::Xml::new(&format!("XML:{}", e)))),
            S::Dynamic(_) => None,
        },

        // DEFINE_VARIABLE
        "RESPONSE_CONTENT_TYPE" => single!(response_content_type::ResponseContentType::new()),
        "ARGS_COMBINED_SIZE" => single!(args_combined_size::ArgsCombinedSize::new()),
        "AUTH_TYPE" => single!(auth_type::AuthType::new()),
        "FILES_COMBINED_SIZE" => single!(files_combined_size::FilesCombinedSize::new()),
        "FULL_REQUEST" => single!(full_request::FullRequest::new()),
        "FULL_REQUEST_LENGTH" => single!(full_request_length::FullRequestLength::new()),
        "INBOUND_DATA_ERROR" => single!(inbound_data_error::InboundDataError::new()),
        "MATCHED_VAR" => single!(matched_var::MatchedVar::new()),
        "MATCHED_VAR_NAME" => single!(matched_var_name::MatchedVarName::new()),
        "MSC_PCRE_ERROR" => single!(msc_pcre_error::MscPcreError::new()),
        "MSC_PCRE_LIMITS_EXCEEDED" => single!(msc_pcre_limits_exceeded::MscPcreLimitsExceeded::new()),
        "MULTIPART_BOUNDARY_QUOTED" => single!(multipart_boundary_quoted::MultipartBoundaryQuoted::new()),
        "MULTIPART_BOUNDARY_WHITESPACE" => single!(multipart_boundary_whitespace::MultipartBoundaryWhiteSpace::new()),
        "MULTIPART_CRLF_LF_LINES" => single!(multipart_crlf_lf_lines::MultipartCrlfLFLines::new()),
        "MULTIPART_DATA_AFTER" => single!(multipart_data_after::MultipartDateAfter::new()),
        "MULTIPART_DATA_BEFORE" => single!(multipart_data_before::MultipartDateBefore::new()),
        "MULTIPART_DUPLICATE_PART_HEADER" => {
            single!(multipart_duplicate_part_header::MultipartDuplicatePartHeader::new())
        }
        "MULTIPART_FILE_LIMIT_EXCEEDED" => single!(multipart_file_limit_exceeded::MultipartFileLimitExceeded::new()),
        "MULTIPART_HEADER_FOLDING" => single!(multipart_header_folding::MultipartHeaderFolding::new()),
        "MULTIPART_INVALID_HEADER_FOLDING" => {
            single!(multipart_invalid_header_folding::MultipartInvalidHeaderFolding::new())
        }
        "MULTIPART_INVALID_PART" => single!(multipart_invalid_part::MultipartInvalidPart::new()),
        "MULTIPART_INVALID_QUOTING" => single!(multipart_invalid_quoting::MultipartInvalidQuoting::new()),
        "MULTIPART_LF_LINE" => single!(multipart_lf_line::MultipartLFLine::new()),
        "MULTIPART_MISSING_SEMICOLON" | "MULTIPART_SEMICOLON_MISSING" => {
            single!(multipart_missing_semicolon::MultipartMissingSemicolon::new())
        }
        "MULTIPART_STRICT_ERROR" => single!(multipart_strict_error::MultipartStrictError::new()),
        "MULTIPART_UNMATCHED_BOUNDARY" => single!(multipart_unmatched_boundary::MultipartUnmatchedBoundary::new()),
        "OUTBOUND_DATA_ERROR" => single!(outbound_data_error::OutboundDataError::new()),
        "PATH_INFO" => single!(path_info::PathInfo::new()),
        "QUERY_STRING" => single!(query_string::QueryString::new()),
        "REMOTE_ADDR" => single!(remote_addr::RemoteAddr::new()),
        "REMOTE_HOST" => single!(remote_host::RemoteHost::new()),
        "REMOTE_PORT" => single!(remote_port::RemotePort::new()),
        "REQBODY_ERROR" => single!(reqbody_error::ReqbodyError::new()),
        "REQBODY_ERROR_MSG" => single!(reqbody_error_msg::ReqbodyErrorMsg::new()),
        "REQBODY_PROCESSOR" => single!(reqbody_processor::ReqbodyProcessor::new()),
        "REQBODY_PROCESSOR_ERROR" => single!(reqbody_processor_error::ReqbodyProcessorError::new()),
        "REQBODY_PROCESSOR_ERROR_MSG" => single!(reqbody_processor_error_msg::ReqbodyProcessorErrorMsg::new()),
        "REQUEST_BASENAME" => single!(request_base_name::RequestBasename::new()),
        "REQUEST_BODY" => single!(request_body::RequestBody::new()),
        "REQUEST_BODY_LENGTH" => single!(request_body_length::RequestBodyLength::new()),
        "REQUEST_FILENAME" => single!(request_file_name::RequestFilename::new()),
        "REQUEST_LINE" => single!(request_line::RequestLine::new()),
        "REQUEST_METHOD" => single!(request_method::RequestMethod::new()),
        "REQUEST_PROTOCOL" => single!(request_protocol::RequestProtocol::new()),
        "REQUEST_URI" => single!(request_uri::RequestURI::new()),
        "REQUEST_URI_RAW" => single!(request_uri_raw::RequestURIRaw::new()),
        "RESPONSE_BODY" => single!(response_body::ResponseBody::new()),
        "RESPONSE_CONTENT_LENGTH" => single!(response_content_length::ResponseContentLength::new()),
        "RESPONSE_PROTOCOL" => single!(response_protocol::ResponseProtocol::new()),
        "RESPONSE_STATUS" => single!(response_status::ResponseStatus::new()),
        "SERVER_ADDR" => single!(server_addr::ServerAddr::new()),
        "SERVER_NAME" => single!(server_name::ServerName::new()),
        "SERVER_PORT" => single!(server_port::ServerPort::new()),
        "SESSIONID" => single!(session_id::SessionID::new()),
        "UNIQUE_ID" => single!(unique_id::UniqueID::new()),
        "URLENCODED_ERROR" => single!(url_encoded_error::UrlEncodedError::new()),
        "USERID" => single!(user_id::UserID::new()),
        "STATUS" | "STATUS_LINE" => single!(status::Status::new()),
        "WEBAPPID" => single!(web_app_id::WebAppId::new()),

        // RUN_TIME_VAR_*: named after the token text as written.
        "DURATION" => single!(duration::Duration::new(name)),
        "MODSEC_BUILD" => single!(modsec_build::ModsecBuild::new(name)),
        "HIGHEST_SEVERITY" => single!(highest_severity::HighestSeverity::new(name)),
        "REMOTE_USER" => single!(remote_user::RemoteUser::new(name)),
        "TIME" => single!(time::Time::new(name)),
        "TIME_DAY" => single!(time_day::TimeDay::new(name)),
        "TIME_EPOCH" => single!(time_epoch::TimeEpoch::new(name)),
        "TIME_HOUR" => single!(time_hour::TimeHour::new(name)),
        "TIME_MIN" => single!(time_min::TimeMin::new(name)),
        "TIME_MON" => single!(time_mon::TimeMon::new(name)),
        "TIME_SEC" => single!(time_sec::TimeSec::new(name)),
        "TIME_WDAY" => single!(time_wday::TimeWDay::new(name)),
        "TIME_YEAR" => single!(time_year::TimeYear::new(name)),

        // `WEBSERVER_ERROR_LOG` is rejected by the C++ scanner ("not
        // supported by libModSecurity"); anything else is unknown.
        _ => None,
    }
}

/// Helpers shared by the unit tests of the variables and of the Lua engine.
#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::{Arc, Mutex};

    use crate::debug_log::debug_log::DebugLog;
    use crate::rules_set::RulesSet;

    /// A debug log that keeps the messages in memory.
    #[derive(Debug, Default)]
    pub struct CaptureLog {
        pub log: Arc<Mutex<String>>,
    }

    impl DebugLog for CaptureLog {
        fn write(&self, level: i32, msg: &str) {
            self.log.lock().unwrap().push_str(&format!("[{}] {}\n", level, msg));
        }
        fn write_ctx(&self, level: i32, _id: &str, _uri: &str, msg: &str) {
            self.write(level, msg);
        }
        fn is_log_file_set(&self) -> bool {
            false
        }
        fn is_log_level_set(&self) -> bool {
            true
        }
        fn set_debug_log_level(&mut self, _level: i32) {}
        fn set_debug_log_file(&mut self, _file_name: &str) -> Result<(), String> {
            Ok(())
        }
        fn get_debug_log_file(&self) -> &str {
            ""
        }
        fn get_debug_log_level(&self) -> i32 {
            9
        }
        fn debug_level(&self) -> i32 {
            9
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    /// A rule set logging everything (level 9) to the returned buffer.
    pub fn rules_with_log() -> (RulesSet, Arc<Mutex<String>>) {
        let log = Arc::new(Mutex::new(String::new()));
        let rules = RulesSet::with_debug_log(Box::new(CaptureLog { log: log.clone() }));
        (rules, log)
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::rules_with_log;
    use super::variable::{KeyExclusion, Variable};
    use super::*;
    use crate::modsecurity::ModSecurity;
    use crate::rule_with_actions::{RuleWithActions, RuleWithActionsKind};
    use crate::rules_set::RulesSet;
    use crate::run_time_string::RunTimeString;
    use crate::transaction::Transaction;
    use crate::variable_value::VariableValue;

    fn eval(v: &dyn Variable, t: &Transaction<'_>, rule: Option<&RuleWithActions>) -> Vec<(String, String)> {
        let mut l: Vec<VariableValue> = Vec::new();
        v.evaluate(t, rule, &mut l);
        l.iter()
            .map(|v| {
                (
                    String::from_utf8_lossy(v.key_with_collection()).into_owned(),
                    String::from_utf8_lossy(v.value()).into_owned(),
                )
            })
            .collect()
    }

    fn var(token: &str, sel: VariableSelector) -> Box<dyn Variable> {
        new_variable(token, sel).unwrap_or_else(|| panic!("no variable for {}", token))
    }

    fn sel_none() -> VariableSelector {
        VariableSelector::None
    }

    fn sel_key(k: &str) -> VariableSelector {
        VariableSelector::DictElement(k.to_string())
    }

    fn sel_re(k: &str) -> VariableSelector {
        VariableSelector::Regexp(k.to_string())
    }

    fn sel_dyn(k: &str) -> VariableSelector {
        VariableSelector::Dynamic(RunTimeString::from_text(k))
    }

    const DICTS: &[&str] = &[
        "ARGS",
        "ARGS_POST",
        "ARGS_GET",
        "FILES_SIZES",
        "FILES_NAMES",
        "FILES_TMP_CONTENT",
        "MULTIPART_FILENAME",
        "MULTIPART_FILENAME_CHARSET",
        "MULTIPART_FILENAME_LANGUAGE",
        "MULTIPART_NAME",
        "MATCHED_VARS_NAMES",
        "MATCHED_VARS",
        "FILES",
        "REQUEST_COOKIES",
        "REQUEST_HEADERS",
        "RESPONSE_HEADERS",
        "GEO",
        "REQUEST_COOKIES_NAMES",
        "MULTIPART_PART_HEADERS",
        "FILES_TMPNAMES",
        "ARGS_NAMES",
        "ARGS_GET_NAMES",
        "ARGS_POST_NAMES",
        "REQUEST_HEADERS_NAMES",
        "RESPONSE_HEADERS_NAMES",
        "RULE",
    ];
    const COLLECTIONS: &[&str] = &["TX", "IP", "GLOBAL", "SESSION", "USER", "RESOURCE"];
    /// (token, C++ variable name)
    const SINGLES: &[(&str, &str)] = &[
        ("RESPONSE_CONTENT_TYPE", "RESPONSE_CONTENT_TYPE"),
        ("ARGS_COMBINED_SIZE", "ARGS_COMBINED_SIZE"),
        ("AUTH_TYPE", "AUTH_TYPE"),
        ("FILES_COMBINED_SIZE", "FILES_COMBINED_SIZE"),
        ("FULL_REQUEST", "FULL_REQUEST"),
        ("FULL_REQUEST_LENGTH", "FULL_REQUEST_LENGTH"),
        ("INBOUND_DATA_ERROR", "INBOUND_DATA_ERROR"),
        ("MATCHED_VAR", "MATCHED_VAR"),
        ("MATCHED_VAR_NAME", "MATCHED_VAR_NAME"),
        ("MSC_PCRE_ERROR", "MSC_PCRE_ERROR"),
        ("MSC_PCRE_LIMITS_EXCEEDED", "MSC_PCRE_LIMITS_EXCEEDED"),
        ("MULTIPART_BOUNDARY_QUOTED", "MULTIPART_BOUNDARY_QUOTED"),
        ("MULTIPART_BOUNDARY_WHITESPACE", "MULTIPART_BOUNDARY_WHITESPACE"),
        ("MULTIPART_CRLF_LF_LINES", "MULTIPART_CRLF_LF_LINES"),
        ("MULTIPART_DATA_AFTER", "MULTIPART_DATA_AFTER"),
        ("MULTIPART_DATA_BEFORE", "MULTIPART_DATA_BEFORE"),
        ("MULTIPART_DUPLICATE_PART_HEADER", "MULTIPART_DUPLICATE_PART_HEADER"),
        ("MULTIPART_FILE_LIMIT_EXCEEDED", "MULTIPART_FILE_LIMIT_EXCEEDED"),
        ("MULTIPART_HEADER_FOLDING", "MULTIPART_HEADER_FOLDING"),
        ("MULTIPART_INVALID_HEADER_FOLDING", "MULTIPART_INVALID_HEADER_FOLDING"),
        ("MULTIPART_INVALID_PART", "MULTIPART_INVALID_PART"),
        ("MULTIPART_INVALID_QUOTING", "MULTIPART_INVALID_QUOTING"),
        ("MULTIPART_LF_LINE", "MULTIPART_LF_LINE"),
        ("MULTIPART_MISSING_SEMICOLON", "MULTIPART_MISSING_SEMICOLON"),
        ("MULTIPART_SEMICOLON_MISSING", "MULTIPART_MISSING_SEMICOLON"),
        ("MULTIPART_STRICT_ERROR", "MULTIPART_STRICT_ERROR"),
        ("MULTIPART_UNMATCHED_BOUNDARY", "MULTIPART_UNMATCHED_BOUNDARY"),
        ("OUTBOUND_DATA_ERROR", "OUTBOUND_DATA_ERROR"),
        ("PATH_INFO", "PATH_INFO"),
        ("QUERY_STRING", "QUERY_STRING"),
        ("REMOTE_ADDR", "REMOTE_ADDR"),
        ("REMOTE_HOST", "REMOTE_HOST"),
        ("REMOTE_PORT", "REMOTE_PORT"),
        ("REQBODY_ERROR", "REQBODY_ERROR"),
        ("REQBODY_ERROR_MSG", "REQBODY_ERROR_MSG"),
        ("REQBODY_PROCESSOR", "REQBODY_PROCESSOR"),
        ("REQBODY_PROCESSOR_ERROR", "REQBODY_PROCESSOR_ERROR"),
        ("REQBODY_PROCESSOR_ERROR_MSG", "PROCESSOR_ERROR_MSG"),
        ("REQUEST_BASENAME", "REQUEST_BASENAME"),
        ("REQUEST_BODY", "REQUEST_BODY"),
        ("REQUEST_BODY_LENGTH", "REQUEST_BODY_LENGTH"),
        ("REQUEST_FILENAME", "REQUEST_FILENAME"),
        ("REQUEST_LINE", "REQUEST_LINE"),
        ("REQUEST_METHOD", "REQUEST_METHOD"),
        ("REQUEST_PROTOCOL", "REQUEST_PROTOCOL"),
        ("REQUEST_URI", "REQUEST_URI"),
        ("REQUEST_URI_RAW", "REQUEST_URI_RAW"),
        ("RESPONSE_BODY", "RESPONSE_BODY"),
        ("RESPONSE_CONTENT_LENGTH", "RESPONSE_CONTENT_LENGTH"),
        ("RESPONSE_PROTOCOL", "RESPONSE_PROTOCOL"),
        ("RESPONSE_STATUS", "RESPONSE_STATUS"),
        ("SERVER_ADDR", "SERVER_ADDR"),
        ("SERVER_NAME", "SERVER_NAME"),
        ("SERVER_PORT", "SERVER_PORT"),
        ("SESSIONID", "SESSIONID"),
        ("UNIQUE_ID", "UNIQUEID"),
        ("URLENCODED_ERROR", "URLENCODED_ERROR"),
        ("USERID", "USERID"),
        ("STATUS", "STATUS"),
        ("STATUS_LINE", "STATUS"),
        ("WEBAPPID", "WEBAPPID"),
        ("DURATION", "DURATION"),
        ("MODSEC_BUILD", "MODSEC_BUILD"),
        ("HIGHEST_SEVERITY", "HIGHEST_SEVERITY"),
        ("REMOTE_USER", "REMOTE_USER"),
        ("TIME", "TIME"),
        ("TIME_DAY", "TIME_DAY"),
        ("TIME_EPOCH", "TIME_EPOCH"),
        ("TIME_HOUR", "TIME_HOUR"),
        ("TIME_MIN", "TIME_MIN"),
        ("TIME_MON", "TIME_MON"),
        ("TIME_SEC", "TIME_SEC"),
        ("TIME_WDAY", "TIME_WDAY"),
        ("TIME_YEAR", "TIME_YEAR"),
    ];

    #[test]
    fn factory_dict_variables() {
        for &n in DICTS {
            let v = var(n, sel_none());
            assert_eq!(v.full_name(), n);
            assert_eq!(v.collection_name(), n);
            let v = var(n, sel_key("foo"));
            assert_eq!(v.full_name(), format!("{}:foo", n));
            assert_eq!(v.name(), "foo");
            assert!(v.regex().is_none());
            let v = var(n, sel_re("^f"));
            assert_eq!(v.full_name(), format!("{}:regex(^f)", n));
            assert_eq!(v.regex_pattern(), Some("^f"));
            assert!(new_variable(n, sel_dyn("x")).is_none(), "{}", n);
            // Case insensitive token.
            assert!(new_variable(&n.to_lowercase(), sel_none()).is_some());
        }
    }

    #[test]
    fn factory_collections() {
        for &n in COLLECTIONS {
            let v = var(n, sel_none());
            assert_eq!(v.full_name(), n);
            assert!(v.dynamic_name().is_none());
            let v = var(n, sel_key("foo"));
            assert_eq!(v.full_name(), format!("{}:foo", n));
            let v = var(n, sel_re("^f"));
            assert_eq!(v.regex_pattern(), Some("^f"));
            let expected = if n == "RESOURCE" { "RESOURCE::regex(^f)".to_string() } else { format!("{}:regex(^f)", n) };
            assert_eq!(v.full_name(), expected);
            let v = var(n, sel_dyn("x"));
            assert_eq!(v.full_name(), format!("{}:dynamic", n));
            assert!(v.dynamic_name().is_some());
        }
    }

    #[test]
    fn factory_single_and_runtime_variables() {
        for &(token, name) in SINGLES {
            let v = var(token, sel_none());
            assert_eq!(v.full_name(), name, "{}", token);
            assert!(new_variable(token, sel_key("x")).is_none(), "{}", token);
            assert!(new_variable(token, sel_re("x")).is_none(), "{}", token);
            assert!(new_variable(token, sel_dyn("x")).is_none(), "{}", token);
        }
        // RUN_TIME_VAR_*: named after the text as written.
        assert_eq!(var("time_hour", sel_none()).full_name(), "time_hour");
        // ENV and XML.
        assert_eq!(var("ENV", sel_none()).full_name(), "ENV");
        assert_eq!(var("ENV", sel_key("PATH")).full_name(), "ENV:PATH");
        assert_eq!(var("ENV", sel_re("PA")).full_name(), "ENV:PA");
        assert!(new_variable("ENV", sel_dyn("x")).is_none());
        assert_eq!(var("XML", sel_none()).full_name(), "XML");
        assert_eq!(var("XML", sel_key("/a/b")).full_name(), "XML:/a/b");
        assert!(new_variable("XML", sel_dyn("x")).is_none());
        // Unknown / unsupported.
        assert!(new_variable("WEBSERVER_ERROR_LOG", sel_none()).is_none());
        assert!(new_variable("NOT_A_VARIABLE", sel_none()).is_none());
    }

    #[test]
    fn anchored_variables() {
        let ms = ModSecurity::new();
        let rules = RulesSet::new();
        let mut t = Transaction::new(&ms, &rules, None);
        t.process_connection("1.2.3.4", 1234, "5.6.7.8", 80);
        t.process_uri(b"/path/file.php?a=1&b=2&a=3", b"GET", b"1.1");
        t.add_request_header(b"Host", b"example.com");
        t.add_request_header(b"Cookie", b"c1=v1");

        assert_eq!(eval(&*var("REMOTE_ADDR", sel_none()), &t, None), vec![("REMOTE_ADDR".into(), "1.2.3.4".into())]);
        assert_eq!(eval(&*var("REQUEST_METHOD", sel_none()), &t, None), vec![("REQUEST_METHOD".into(), "GET".into())]);
        assert_eq!(eval(&*var("STATUS", sel_none()), &t, None), eval(&*var("RESPONSE_STATUS", sel_none()), &t, None));

        let mut a = eval(&*var("ARGS", sel_none()), &t, None);
        a.sort();
        assert_eq!(
            a,
            vec![("ARGS:a".into(), "1".into()), ("ARGS:a".into(), "3".into()), ("ARGS:b".into(), "2".into())]
        );
        assert_eq!(eval(&*var("ARGS", sel_key("B")), &t, None), vec![("ARGS:b".into(), "2".into())]);
        assert_eq!(eval(&*var("ARGS", sel_re("^b$")), &t, None), vec![("ARGS:b".into(), "2".into())]);

        // Exclusions (`!ARGS:a`).
        let mut args = var("ARGS", sel_none());
        args.base_mut().key_exclusion.push(KeyExclusion::string("a"));
        assert_eq!(eval(&*args, &t, None), vec![("ARGS:b".into(), "2".into())]);

        // The *_NAMES proxies.
        let mut n = eval(&*var("ARGS_NAMES", sel_none()), &t, None);
        n.sort();
        assert_eq!(
            n,
            vec![
                ("ARGS_NAMES:a".into(), "a".into()),
                ("ARGS_NAMES:a".into(), "a".into()),
                ("ARGS_NAMES:b".into(), "b".into())
            ]
        );
        assert_eq!(
            eval(&*var("ARGS_GET_NAMES", sel_key("b")), &t, None),
            vec![("ARGS_GET_NAMES:b".into(), "b".into())]
        );
        assert_eq!(eval(&*var("ARGS_GET_NAMES", sel_re("b")), &t, None), vec![("ARGS_GET_NAMES:b".into(), "b".into())]);
        assert!(eval(&*var("ARGS_POST_NAMES", sel_none()), &t, None).is_empty());

        assert_eq!(
            eval(&*var("REQUEST_HEADERS", sel_key("host")), &t, None),
            vec![("REQUEST_HEADERS:Host".into(), "example.com".into())]
        );
        assert_eq!(
            eval(&*var("REQUEST_COOKIES", sel_none()), &t, None),
            vec![("REQUEST_COOKIES:c1".into(), "v1".into())]
        );
    }

    #[test]
    fn tx_collection() {
        let ms = ModSecurity::new();
        let rules = RulesSet::new();
        let t = Transaction::new(&ms, &rules, None);
        let dynamic = var("TX", sel_dyn("score"));
        dynamic.dynamic_store_or_update_first(&t, b"score", b"5");
        dynamic.dynamic_store_or_update_first(&t, b"other", b"7");

        assert_eq!(eval(&*var("TX", sel_key("score")), &t, None), vec![("TX:score".into(), "5".into())]);
        // The backend names the value with the requested key.
        assert_eq!(eval(&*var("TX", sel_key("SCORE")), &t, None), vec![("TX:SCORE".into(), "5".into())]);
        assert_eq!(eval(&*dynamic, &t, None), vec![("TX:score".into(), "5".into())]);
        assert_eq!(eval(&*var("TX", sel_re("^oth")), &t, None), vec![("TX:other".into(), "7".into())]);
        let mut all = eval(&*var("TX", sel_none()), &t, None);
        all.sort();
        assert_eq!(all, vec![("TX:other".into(), "7".into()), ("TX:score".into(), "5".into())]);

        dynamic.dynamic_del(&t, b"score");
        assert!(eval(&*var("TX", sel_key("score")), &t, None).is_empty());
    }

    #[test]
    fn persistent_collections_are_compartmentalised() {
        let ms = ModSecurity::new();
        let (mut rules, _log) = rules_with_log();
        rules.properties.sec_web_app_id = Some("app".to_string());
        let mut t = Transaction::new(&ms, &rules, None);
        // The persistent collections may live on disk (LMDB): use keys
        // unique to this run.
        let nonce = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        );
        let ip_key = format!("ip-{}", nonce);
        t.collections.ip_collection_key = ip_key.as_bytes().to_vec();
        t.collections.global_collection_key = format!("global-{}", nonce).into_bytes();
        t.collections.session_collection_key = format!("sess-{}", nonce).into_bytes();
        t.collections.user_collection_key = format!("user-{}", nonce).into_bytes();
        t.collections.resource_collection_key = format!("res-{}", nonce).into_bytes();

        for c in ["IP", "GLOBAL", "SESSION", "USER", "RESOURCE"] {
            let d = var(c, sel_dyn("zz"));
            d.dynamic_store_or_update_first(&t, b"key1", b"v1");
            let got = eval(&*var(c, sel_key("key1")), &t, None);
            assert_eq!(got.len(), 1, "{}", c);
            assert_eq!(got[0].1, "v1", "{}", c);
            assert_eq!(eval(&*d, &t, None).len(), 0, "{} (dynamic name `zz`)", c);
        }
        // The stored key carries the collection key and the web app id.
        assert_eq!(
            t.collections.ip_collection.resolve_first(format!("{}::app::key1", ip_key).as_bytes()),
            Some(b"v1".to_vec())
        );

        // IP del uses the same compartments.
        persistent::Persistent::Ip.del(&t, b"key1");
        assert!(eval(&*var("IP", sel_key("key1")), &t, None).is_empty());
        // Sic: SESSION del uses the IP collection key as second compartment,
        // so it does not remove the value.
        persistent::Persistent::Session.del(&t, b"key1");
        assert_eq!(eval(&*var("SESSION", sel_key("key1")), &t, None).len(), 1);
    }

    #[test]
    fn rule_variable_walks_the_chain() {
        let ms = ModSecurity::new();
        let rules = RulesSet::new();
        let mut parent = RuleWithActions::new(None, None, "f", 1, RuleWithActionsKind::Unconditional);
        parent.rule_id = 10;
        parent.rev = "3".to_string();
        let mut sev = crate::actions::severity::Severity::new("severity:2");
        sev.severity = 2;
        let mut child = RuleWithActions::new(
            Some(vec![crate::rule_with_actions::RuleAction::Severity(sev)]),
            None,
            "f",
            2,
            RuleWithActionsKind::Unconditional,
        );
        child.rule_id = 0;
        parent.chained_rule_child = Some(Box::new(child));
        let child = parent.chained_rule_child.as_deref().unwrap();

        let mut t = Transaction::new(&ms, &rules, None);
        // Outside of the chain evaluation the child has no parent.
        assert!(eval(&*var("RULE", sel_key("id")), &t, Some(child)).is_empty());

        t.chained_rule_parents.push(&parent);
        assert_eq!(eval(&*var("RULE", sel_key("id")), &t, Some(child)), vec![("RULE:id".into(), "10".into())]);
        assert_eq!(eval(&*var("RULE", sel_key("rev")), &t, Some(child)), vec![("RULE:rev".into(), "3".into())]);
        assert_eq!(
            eval(&*var("RULE", sel_key("severity")), &t, Some(child)),
            vec![("RULE:severity".into(), "2".into())]
        );
        assert_eq!(eval(&*var("RULE", sel_re("^rev")), &t, Some(child)), vec![("RULE:rev".into(), "3".into())]);
        // Case sensitive element.
        assert!(eval(&*var("RULE", sel_key("ID")), &t, Some(child)).is_empty());
        assert_eq!(
            eval(&*var("RULE", sel_none()), &t, Some(child)),
            vec![
                ("RULE:id".into(), "10".into()),
                ("RULE:rev".into(), "3".into()),
                ("RULE:severity".into(), "2".into())
            ]
        );
        // No rule: id is still looked up (finds nothing), rev needs a rule.
        assert!(eval(&*var("RULE", sel_key("id")), &t, None).is_empty());
        let mut l = Vec::new();
        var("RULE", sel_key("id")).evaluate(&t, Some(&parent), &mut l);
        assert_eq!(l[0].origin().len(), 1);
    }

    #[test]
    fn env_variable() {
        let ms = ModSecurity::new();
        let rules = RulesSet::new();
        let mut t = Transaction::new(&ms, &rules, None);
        t.variable_envs.insert(b"modfoo".to_vec(), b"bar".to_vec());
        // SAFETY: the tests of this module do not read this variable
        // concurrently.
        unsafe { std::env::set_var("MSRS_TEST_ENV", "regression tests") };

        assert_eq!(eval(&*var("ENV", sel_key("modfoo")), &t, None), vec![("ENV:modfoo".into(), "bar".into())]);
        assert!(eval(&*var("ENV", sel_key("MODFOO")), &t, None).is_empty());
        assert_eq!(
            eval(&*var("ENV", sel_key("MSRS_TEST_ENV")), &t, None),
            vec![("ENV:MSRS_TEST_ENV".into(), "regression tests".into())]
        );
        let all = eval(&*var("ENV", sel_none()), &t, None);
        assert!(all.contains(&("ENV:modfoo".into(), "bar".into())));
        assert!(all.contains(&("ENV:MSRS_TEST_ENV".into(), "regression tests".into())));
        // setenv wins over the process environment.
        t.variable_envs.insert(b"MSRS_TEST_ENV".to_vec(), b"mine".to_vec());
        assert_eq!(eval(&*var("ENV", sel_key("MSRS_TEST_ENV")), &t, None)[0].1, "mine");
        // Exclusions.
        let mut e = var("ENV", sel_none());
        e.base_mut().key_exclusion.push(KeyExclusion::string("modfoo"));
        assert!(!eval(&*e, &t, None).iter().any(|(k, _)| k == "ENV:modfoo"));
    }

    #[test]
    fn remote_user() {
        let ms = ModSecurity::new();
        let rules = RulesSet::new();
        let mut t = Transaction::new(&ms, &rules, None);
        assert!(eval(&*var("REMOTE_USER", sel_none()), &t, None).is_empty());
        assert_eq!(remote_user::RemoteUser::compute(&t), b"");
        t.add_request_header(b"Authorization", b"Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
        let got = eval(&*var("REMOTE_USER", sel_none()), &t, None);
        assert_eq!(got, vec![("REQUEST_HEADERS:Authorization".into(), "Aladdin".into())]);
        assert_eq!(remote_user::RemoteUser::compute(&t), b"Aladdin");

        let mut t = Transaction::new(&ms, &rules, None);
        t.add_request_header(b"Authorization", b"Digest QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
        assert!(eval(&*var("REMOTE_USER", sel_none()), &t, None).is_empty());
    }

    #[test]
    fn computed_variables() {
        let ms = ModSecurity::new();
        let (mut rules, _log) = rules_with_log();
        rules.properties.sec_web_app_id = Some("bisteka".to_string());
        let t = Transaction::new(&ms, &rules, None);

        assert_eq!(
            eval(&*var("MODSEC_BUILD", sel_none()), &t, None),
            vec![("MODSEC_BUILD".into(), "030017100".into())]
        );
        assert_eq!(
            eval(&*var("HIGHEST_SEVERITY", sel_none()), &t, None),
            vec![("HIGHEST_SEVERITY".into(), "255".into())]
        );
        // Sic: WEBAPPID values are named with the (empty) `m_name`.
        assert_eq!(eval(&*var("WEBAPPID", sel_none()), &t, None), vec![("".into(), "bisteka".into())]);

        let d = eval(&*var("DURATION", sel_none()), &t, None);
        assert_eq!(d[0].0, "DURATION");
        assert!(d[0].1.contains('.') && d[0].1.split('.').nth(1).unwrap().len() == 6);

        let all_digits = |s: &str| !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit());
        for (tok, len) in
            [("TIME_DAY", 2), ("TIME_HOUR", 2), ("TIME_MIN", 2), ("TIME_SEC", 2), ("TIME_WDAY", 1), ("TIME_YEAR", 4)]
        {
            let v = eval(&*var(tok, sel_none()), &t, None);
            assert_eq!(v[0].0, tok);
            assert!(all_digits(&v[0].1) && v[0].1.len() == len, "{} {}", tok, v[0].1);
        }
        let mon: i32 = eval(&*var("TIME_MON", sel_none()), &t, None)[0].1.parse().unwrap();
        assert!((1..=12).contains(&mon));
        assert!(all_digits(&eval(&*var("TIME_EPOCH", sel_none()), &t, None)[0].1));
        let time = &eval(&*var("TIME", sel_none()), &t, None)[0];
        assert_eq!(time.0, "TIME");
        assert_eq!(time.1.len(), 8);
        assert_eq!(&time.1[2..3], ":");
    }
}
