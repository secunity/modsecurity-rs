//! `variables` (C++ `src/variables/`): the targets of rules.
//!
//! [`variable::Variable`] is a target; [`new_variable`] builds it from its
//! name in the rule (the `var:` rule of the C++ grammar). The C++ project
//! has one header per variable, each defining one to three classes with the
//! `DEFINE_VARIABLE*` macros; here those are rows of the table in
//! [`new_variable`]. The variables with logic of their own have a module:
//! the collections ([`persistent`], and `TX` in [`variable`]), [`rule`],
//! [`env`], [`xml`] and the [`computed`] ones (`TIME*`, `DURATION`, ...).

pub(crate) mod computed;
pub mod env;
pub mod persistent;
pub mod rule;
pub mod variable;
pub mod xml;

use crate::anchored_set_variable::AnchoredSetVariable;
use crate::anchored_set_variable_translation_proxy::AnchoredSetVariableTranslationProxy;
use crate::anchored_variable::AnchoredVariable;
use crate::transaction::TransactionAnchoredVariables as Vars;
use crate::utils::regex::Regex;
use variable::{CollectionKey, Source, Variable, regex_name};

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
/// | the multi valued variables (`ARGS`, `REQUEST_HEADERS`, `FILES`, ..., and their `*_NAMES`), `RULE` | all entries | one key | keys matching | - |
/// | `TX`, `IP`, `GLOBAL`, `SESSION`, `USER`, `RESOURCE` | all entries | one key | keys matching | key from macros |
/// | `ENV` | all | `ENV:e` | `ENV:r` | - |
/// | `XML` | the document | `XML:e` (XPath) | `XML:r` (XPath) | - |
/// | every single valued variable (`REQUEST_METHOD`, `TIME`, `DURATION`, ...) | the value | - | - | - |
///
/// (The `ENV:/regex/` and `XML:/regex/` forms are not regular expressions
/// in C++ either: the text between the slashes is used as the key.)
pub fn new_variable(name: &str, selector: VariableSelector) -> Option<Variable> {
    use VariableSelector as S;
    use computed::Computed as C;
    use persistent::Persistent;

    /// A single valued variable: the transaction field `$field`.
    macro_rules! single {
        ($n:literal, $field:ident) => {{
            fn get(v: &Vars) -> &AnchoredVariable {
                &v.$field
            }
            match selector {
                S::None => Some(Variable::new($n, Source::Single(get))),
                _ => None,
            }
        }};
    }
    /// A multi valued variable: the transaction field `$field`.
    macro_rules! set {
        ($n:literal, $field:ident) => {{
            fn get(v: &Vars) -> &AnchoredSetVariable {
                &v.$field
            }
            let (name, selector) = Variable::selected($n, selector)?;
            Some(Variable::new(&name, Source::Set(get, selector)))
        }};
    }
    /// The names of the multi valued variable `$fount`, through the proxy
    /// `$field`.
    macro_rules! names {
        ($n:literal, $field:ident, $fount:ident) => {{
            fn get(v: &Vars) -> (&AnchoredSetVariableTranslationProxy, &AnchoredSetVariable) {
                (&v.$field, &v.$fount)
            }
            let (name, selector) = Variable::selected($n, selector)?;
            Some(Variable::new(&name, Source::Names(get, selector)))
        }};
    }
    // A computed variable, named after the token text as written in the
    // rule (the `RUN_TIME_VAR_*` tokens).
    let computed = |selector: VariableSelector, c: C| match selector {
        S::None => Some(Variable::new(name, Source::Computed(c))),
        _ => None,
    };

    let token = name.to_ascii_uppercase();
    match token.as_str() {
        // Multi valued (C++ DEFINE_VARIABLE_DICT)
        "ARGS" => set!("ARGS", args),
        "ARGS_POST" => set!("ARGS_POST", args_post),
        "ARGS_GET" => set!("ARGS_GET", args_get),
        "FILES_SIZES" => set!("FILES_SIZES", files_sizes),
        "FILES_NAMES" => set!("FILES_NAMES", files_names),
        "FILES_TMP_CONTENT" => set!("FILES_TMP_CONTENT", files_tmp_content),
        "MULTIPART_FILENAME" => set!("MULTIPART_FILENAME", multipart_file_name),
        "MULTIPART_FILENAME_CHARSET" => set!("MULTIPART_FILENAME_CHARSET", multipart_file_name_charset),
        "MULTIPART_FILENAME_LANGUAGE" => set!("MULTIPART_FILENAME_LANGUAGE", multipart_file_name_language),
        "MULTIPART_NAME" => set!("MULTIPART_NAME", multipart_name),
        "MATCHED_VARS_NAMES" => set!("MATCHED_VARS_NAMES", matched_vars_names),
        "MATCHED_VARS" => set!("MATCHED_VARS", matched_vars),
        "FILES" => set!("FILES", files),
        "REQUEST_COOKIES" => set!("REQUEST_COOKIES", request_cookies),
        "REQUEST_HEADERS" => set!("REQUEST_HEADERS", request_headers),
        "RESPONSE_HEADERS" => set!("RESPONSE_HEADERS", response_headers),
        "GEO" => set!("GEO", geo),
        "REQUEST_COOKIES_NAMES" => set!("REQUEST_COOKIES_NAMES", request_cookies_names),
        "MULTIPART_PART_HEADERS" => set!("MULTIPART_PART_HEADERS", multipart_part_headers),
        "FILES_TMPNAMES" => set!("FILES_TMPNAMES", files_tmp_names),
        "REQUEST_HEADERS_NAMES" => set!("REQUEST_HEADERS_NAMES", request_headers_names),
        "RESPONSE_HEADERS_NAMES" => set!("RESPONSE_HEADERS_NAMES", response_headers_names),
        "ARGS_NAMES" => names!("ARGS_NAMES", args_names, args),
        "ARGS_GET_NAMES" => names!("ARGS_GET_NAMES", args_get_names, args_get),
        "ARGS_POST_NAMES" => names!("ARGS_POST_NAMES", args_post_names, args_post),

        "RULE" => {
            let (name, selector) = Variable::selected(rule::RULE, selector)?;
            Some(Variable::new(&name, Source::Rule(selector)))
        }

        // Collections
        "RESOURCE" => Some(Persistent::Resource.variable(selector)),
        "IP" => Some(Persistent::Ip.variable(selector)),
        "GLOBAL" => Some(Persistent::Global.variable(selector)),
        "USER" => Some(Persistent::User.variable(selector)),
        "SESSION" => Some(Persistent::Session.variable(selector)),
        "TX" => {
            let (name, key) = match selector {
                S::None => ("TX".to_string(), CollectionKey::All),
                S::DictElement(e) => (format!("TX:{}", e), CollectionKey::Key),
                S::Regexp(r) => (regex_name("TX", &r), CollectionKey::Regex(Regex::new_case(&r, true), r)),
                S::Dynamic(m) => ("TX:dynamic".to_string(), CollectionKey::Dynamic(m)),
            };
            Some(Variable::new(&name, Source::Tx(key)))
        }

        // RUN_TIME_VAR_ENV / RUN_TIME_VAR_XML
        "ENV" => match selector {
            S::None => Some(Variable::new("ENV", Source::Env)),
            S::DictElement(e) | S::Regexp(e) => Some(Variable::new(&format!("ENV:{}", e), Source::Env)),
            S::Dynamic(_) => None,
        },
        "XML" => match selector {
            S::None => Some(Variable::new("XML", Source::XmlDocument)),
            S::DictElement(e) | S::Regexp(e) => Some(Variable::new(&format!("XML:{}", e), Source::XmlPath)),
            S::Dynamic(_) => None,
        },

        // Single valued (C++ DEFINE_VARIABLE). The name is the one of the
        // C++ class, which for a few differs from the token (sic).
        "RESPONSE_CONTENT_TYPE" => single!("RESPONSE_CONTENT_TYPE", response_content_type),
        "ARGS_COMBINED_SIZE" => single!("ARGS_COMBINED_SIZE", args_combined_size),
        "AUTH_TYPE" => single!("AUTH_TYPE", auth_type),
        "FILES_COMBINED_SIZE" => single!("FILES_COMBINED_SIZE", files_combined_size),
        "FULL_REQUEST" => single!("FULL_REQUEST", full_request),
        "FULL_REQUEST_LENGTH" => single!("FULL_REQUEST_LENGTH", full_request_length),
        "INBOUND_DATA_ERROR" => single!("INBOUND_DATA_ERROR", inbound_data_error),
        "MATCHED_VAR" => single!("MATCHED_VAR", matched_var),
        "MATCHED_VAR_NAME" => single!("MATCHED_VAR_NAME", matched_var_name),
        "MSC_PCRE_ERROR" => single!("MSC_PCRE_ERROR", msc_pcre_error),
        "MSC_PCRE_LIMITS_EXCEEDED" => single!("MSC_PCRE_LIMITS_EXCEEDED", msc_pcre_limits_exceeded),
        "MULTIPART_BOUNDARY_QUOTED" => single!("MULTIPART_BOUNDARY_QUOTED", multipart_boundary_quoted),
        "MULTIPART_BOUNDARY_WHITESPACE" => single!("MULTIPART_BOUNDARY_WHITESPACE", multipart_boundary_white_space),
        "MULTIPART_CRLF_LF_LINES" => single!("MULTIPART_CRLF_LF_LINES", multipart_crlf_lf_lines),
        "MULTIPART_DATA_AFTER" => single!("MULTIPART_DATA_AFTER", multipart_data_after),
        "MULTIPART_DATA_BEFORE" => single!("MULTIPART_DATA_BEFORE", multipart_data_before),
        "MULTIPART_DUPLICATE_PART_HEADER" => {
            single!("MULTIPART_DUPLICATE_PART_HEADER", multipart_duplicate_part_header)
        }
        "MULTIPART_FILE_LIMIT_EXCEEDED" => single!("MULTIPART_FILE_LIMIT_EXCEEDED", multipart_file_limit_exceeded),
        "MULTIPART_HEADER_FOLDING" => single!("MULTIPART_HEADER_FOLDING", multipart_header_folding),
        "MULTIPART_INVALID_HEADER_FOLDING" => {
            single!("MULTIPART_INVALID_HEADER_FOLDING", multipart_invalid_header_folding)
        }
        "MULTIPART_INVALID_PART" => single!("MULTIPART_INVALID_PART", multipart_invalid_part),
        "MULTIPART_INVALID_QUOTING" => single!("MULTIPART_INVALID_QUOTING", multipart_invalid_quoting),
        "MULTIPART_LF_LINE" => single!("MULTIPART_LF_LINE", multipart_lf_line),
        "MULTIPART_MISSING_SEMICOLON" | "MULTIPART_SEMICOLON_MISSING" => {
            single!("MULTIPART_MISSING_SEMICOLON", multipart_missing_semicolon)
        }
        "MULTIPART_STRICT_ERROR" => single!("MULTIPART_STRICT_ERROR", multipart_strict_error),
        "MULTIPART_UNMATCHED_BOUNDARY" => single!("MULTIPART_UNMATCHED_BOUNDARY", multipart_unmatched_boundary),
        "OUTBOUND_DATA_ERROR" => single!("OUTBOUND_DATA_ERROR", outbound_data_error),
        "PATH_INFO" => single!("PATH_INFO", path_info),
        "QUERY_STRING" => single!("QUERY_STRING", query_string),
        "REMOTE_ADDR" => single!("REMOTE_ADDR", remote_addr),
        "REMOTE_HOST" => single!("REMOTE_HOST", remote_host),
        "REMOTE_PORT" => single!("REMOTE_PORT", remote_port),
        "REQBODY_ERROR" => single!("REQBODY_ERROR", reqbody_error),
        "REQBODY_ERROR_MSG" => single!("REQBODY_ERROR_MSG", reqbody_error_msg),
        "REQBODY_PROCESSOR" => single!("REQBODY_PROCESSOR", reqbody_processor),
        "REQBODY_PROCESSOR_ERROR" => single!("REQBODY_PROCESSOR_ERROR", reqbody_processor_error),
        "REQBODY_PROCESSOR_ERROR_MSG" => single!("PROCESSOR_ERROR_MSG", reqbody_processor_error_msg),
        "REQUEST_BASENAME" => single!("REQUEST_BASENAME", request_basename),
        "REQUEST_BODY" => single!("REQUEST_BODY", request_body),
        "REQUEST_BODY_LENGTH" => single!("REQUEST_BODY_LENGTH", request_body_length),
        "REQUEST_FILENAME" => single!("REQUEST_FILENAME", request_filename),
        "REQUEST_LINE" => single!("REQUEST_LINE", request_line),
        "REQUEST_METHOD" => single!("REQUEST_METHOD", request_method),
        "REQUEST_PROTOCOL" => single!("REQUEST_PROTOCOL", request_protocol),
        "REQUEST_URI" => single!("REQUEST_URI", request_uri),
        "REQUEST_URI_RAW" => single!("REQUEST_URI_RAW", request_uri_raw),
        "RESPONSE_BODY" => single!("RESPONSE_BODY", response_body),
        "RESPONSE_CONTENT_LENGTH" => single!("RESPONSE_CONTENT_LENGTH", response_content_length),
        "RESPONSE_PROTOCOL" => single!("RESPONSE_PROTOCOL", response_protocol),
        "RESPONSE_STATUS" => single!("RESPONSE_STATUS", response_status),
        "SERVER_ADDR" => single!("SERVER_ADDR", server_addr),
        "SERVER_NAME" => single!("SERVER_NAME", server_name),
        "SERVER_PORT" => single!("SERVER_PORT", server_port),
        "SESSIONID" => single!("SESSIONID", session_id),
        "UNIQUE_ID" => single!("UNIQUEID", unique_id),
        "URLENCODED_ERROR" => single!("URLENCODED_ERROR", url_encoded_error),
        "USERID" => single!("USERID", user_id),
        "STATUS" | "STATUS_LINE" => single!("STATUS", response_status),
        "WEBAPPID" => match selector {
            S::None => Some(Variable::new("WEBAPPID", Source::Computed(C::WebAppId))),
            _ => None,
        },

        "DURATION" => computed(selector, C::Duration),
        "MODSEC_BUILD" => computed(selector, C::ModsecBuild),
        "HIGHEST_SEVERITY" => computed(selector, C::HighestSeverity),
        "REMOTE_USER" => computed(selector, C::RemoteUser),
        "TIME" => computed(selector, C::Time),
        "TIME_DAY" => computed(selector, C::TimeDay),
        "TIME_EPOCH" => computed(selector, C::TimeEpoch),
        "TIME_HOUR" => computed(selector, C::TimeHour),
        "TIME_MIN" => computed(selector, C::TimeMin),
        "TIME_MON" => computed(selector, C::TimeMon),
        "TIME_SEC" => computed(selector, C::TimeSec),
        "TIME_WDAY" => computed(selector, C::TimeWDay),
        "TIME_YEAR" => computed(selector, C::TimeYear),

        // `WEBSERVER_ERROR_LOG` is rejected by the C++ scanner ("not
        // supported by libModSecurity"); anything else is unknown.
        _ => None,
    }
}

/// Helpers shared by the unit tests of the variables and of the Lua engine.
#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::{Arc, Mutex};

    use crate::debug_log::DebugLog;
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
        fn level(&self) -> Option<i32> {
            Some(9)
        }
        fn set_level(&mut self, _level: i32) {}
        fn file(&self) -> Option<&str> {
            None
        }
        fn set_file(&mut self, _file_name: &str) -> Result<(), String> {
            Ok(())
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

    fn eval(v: &Variable, t: &Transaction<'_>, rule: Option<&RuleWithActions>) -> Vec<(String, String)> {
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

    fn var(token: &str, sel: VariableSelector) -> Variable {
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
            assert_eq!(v.regex().map(|r| r.pattern.as_str()), Some("^f"));
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
            assert_eq!(v.regex().map(|r| r.pattern.as_str()), Some("^f"));
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

        assert_eq!(eval(&var("REMOTE_ADDR", sel_none()), &t, None), vec![("REMOTE_ADDR".into(), "1.2.3.4".into())]);
        assert_eq!(eval(&var("REQUEST_METHOD", sel_none()), &t, None), vec![("REQUEST_METHOD".into(), "GET".into())]);
        assert_eq!(eval(&var("STATUS", sel_none()), &t, None), eval(&var("RESPONSE_STATUS", sel_none()), &t, None));

        let mut a = eval(&var("ARGS", sel_none()), &t, None);
        a.sort();
        assert_eq!(
            a,
            vec![("ARGS:a".into(), "1".into()), ("ARGS:a".into(), "3".into()), ("ARGS:b".into(), "2".into())]
        );
        assert_eq!(eval(&var("ARGS", sel_key("B")), &t, None), vec![("ARGS:b".into(), "2".into())]);
        assert_eq!(eval(&var("ARGS", sel_re("^b$")), &t, None), vec![("ARGS:b".into(), "2".into())]);

        // Exclusions (`!ARGS:a`).
        let mut args = var("ARGS", sel_none());
        args.exclude(KeyExclusion::string("a"));
        assert_eq!(eval(&args, &t, None), vec![("ARGS:b".into(), "2".into())]);

        // The *_NAMES proxies.
        let mut n = eval(&var("ARGS_NAMES", sel_none()), &t, None);
        n.sort();
        assert_eq!(
            n,
            vec![
                ("ARGS_NAMES:a".into(), "a".into()),
                ("ARGS_NAMES:a".into(), "a".into()),
                ("ARGS_NAMES:b".into(), "b".into())
            ]
        );
        assert_eq!(eval(&var("ARGS_GET_NAMES", sel_key("b")), &t, None), vec![("ARGS_GET_NAMES:b".into(), "b".into())]);
        assert_eq!(eval(&var("ARGS_GET_NAMES", sel_re("b")), &t, None), vec![("ARGS_GET_NAMES:b".into(), "b".into())]);
        assert!(eval(&var("ARGS_POST_NAMES", sel_none()), &t, None).is_empty());

        assert_eq!(
            eval(&var("REQUEST_HEADERS", sel_key("host")), &t, None),
            vec![("REQUEST_HEADERS:Host".into(), "example.com".into())]
        );
        assert_eq!(
            eval(&var("REQUEST_COOKIES", sel_none()), &t, None),
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

        assert_eq!(eval(&var("TX", sel_key("score")), &t, None), vec![("TX:score".into(), "5".into())]);
        // The backend names the value with the requested key.
        assert_eq!(eval(&var("TX", sel_key("SCORE")), &t, None), vec![("TX:SCORE".into(), "5".into())]);
        assert_eq!(eval(&dynamic, &t, None), vec![("TX:score".into(), "5".into())]);
        assert_eq!(eval(&var("TX", sel_re("^oth")), &t, None), vec![("TX:other".into(), "7".into())]);
        let mut all = eval(&var("TX", sel_none()), &t, None);
        all.sort();
        assert_eq!(all, vec![("TX:other".into(), "7".into()), ("TX:score".into(), "5".into())]);

        dynamic.dynamic_del(&t, b"score");
        assert!(eval(&var("TX", sel_key("score")), &t, None).is_empty());
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
            let got = eval(&var(c, sel_key("key1")), &t, None);
            assert_eq!(got.len(), 1, "{}", c);
            assert_eq!(got[0].1, "v1", "{}", c);
            assert_eq!(eval(&d, &t, None).len(), 0, "{} (dynamic name `zz`)", c);
        }
        // The stored key carries the collection key and the web app id.
        assert_eq!(
            t.collections.ip_collection.resolve_first(format!("{}::app::key1", ip_key).as_bytes()),
            Some(b"v1".to_vec())
        );

        // IP del uses the same compartments.
        persistent::Persistent::Ip.del(&t, b"key1");
        assert!(eval(&var("IP", sel_key("key1")), &t, None).is_empty());
        // Sic: SESSION del uses the IP collection key as second compartment,
        // so it does not remove the value.
        persistent::Persistent::Session.del(&t, b"key1");
        assert_eq!(eval(&var("SESSION", sel_key("key1")), &t, None).len(), 1);
    }

    #[test]
    fn rule_variable_walks_the_chain() {
        let ms = ModSecurity::new();
        let rules = RulesSet::new();
        let mut parent = RuleWithActions::new(None, None, "f", 1, RuleWithActionsKind::Unconditional);
        parent.rule_id = 10;
        parent.rev = "3".to_string();
        let sev = crate::actions::severity::Severity::new("severity:2").unwrap();
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
        assert!(eval(&var("RULE", sel_key("id")), &t, Some(child)).is_empty());

        t.chained_rule_parents.push(&parent);
        assert_eq!(eval(&var("RULE", sel_key("id")), &t, Some(child)), vec![("RULE:id".into(), "10".into())]);
        assert_eq!(eval(&var("RULE", sel_key("rev")), &t, Some(child)), vec![("RULE:rev".into(), "3".into())]);
        assert_eq!(
            eval(&var("RULE", sel_key("severity")), &t, Some(child)),
            vec![("RULE:severity".into(), "2".into())]
        );
        assert_eq!(eval(&var("RULE", sel_re("^rev")), &t, Some(child)), vec![("RULE:rev".into(), "3".into())]);
        // Case sensitive element.
        assert!(eval(&var("RULE", sel_key("ID")), &t, Some(child)).is_empty());
        assert_eq!(
            eval(&var("RULE", sel_none()), &t, Some(child)),
            vec![
                ("RULE:id".into(), "10".into()),
                ("RULE:rev".into(), "3".into()),
                ("RULE:severity".into(), "2".into())
            ]
        );
        // No rule: id is still looked up (finds nothing), rev needs a rule.
        assert!(eval(&var("RULE", sel_key("id")), &t, None).is_empty());
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

        assert_eq!(eval(&var("ENV", sel_key("modfoo")), &t, None), vec![("ENV:modfoo".into(), "bar".into())]);
        assert!(eval(&var("ENV", sel_key("MODFOO")), &t, None).is_empty());
        assert_eq!(
            eval(&var("ENV", sel_key("MSRS_TEST_ENV")), &t, None),
            vec![("ENV:MSRS_TEST_ENV".into(), "regression tests".into())]
        );
        let all = eval(&var("ENV", sel_none()), &t, None);
        assert!(all.contains(&("ENV:modfoo".into(), "bar".into())));
        assert!(all.contains(&("ENV:MSRS_TEST_ENV".into(), "regression tests".into())));
        // setenv wins over the process environment.
        t.variable_envs.insert(b"MSRS_TEST_ENV".to_vec(), b"mine".to_vec());
        assert_eq!(eval(&var("ENV", sel_key("MSRS_TEST_ENV")), &t, None)[0].1, "mine");
        // Exclusions.
        let mut e = var("ENV", sel_none());
        e.exclude(KeyExclusion::string("modfoo"));
        assert!(!eval(&e, &t, None).iter().any(|(k, _)| k == "ENV:modfoo"));
    }

    #[test]
    fn remote_user() {
        let ms = ModSecurity::new();
        let rules = RulesSet::new();
        let mut t = Transaction::new(&ms, &rules, None);
        assert!(eval(&var("REMOTE_USER", sel_none()), &t, None).is_empty());
        assert_eq!(computed::remote_user_name(&t), b"");
        t.add_request_header(b"Authorization", b"Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
        let got = eval(&var("REMOTE_USER", sel_none()), &t, None);
        assert_eq!(got, vec![("REQUEST_HEADERS:Authorization".into(), "Aladdin".into())]);
        assert_eq!(computed::remote_user_name(&t), b"Aladdin");

        let mut t = Transaction::new(&ms, &rules, None);
        t.add_request_header(b"Authorization", b"Digest QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
        assert!(eval(&var("REMOTE_USER", sel_none()), &t, None).is_empty());
    }

    #[test]
    fn computed_variables() {
        let ms = ModSecurity::new();
        let (mut rules, _log) = rules_with_log();
        rules.properties.sec_web_app_id = Some("bisteka".to_string());
        let t = Transaction::new(&ms, &rules, None);

        assert_eq!(eval(&var("MODSEC_BUILD", sel_none()), &t, None), vec![("MODSEC_BUILD".into(), "030017100".into())]);
        assert_eq!(
            eval(&var("HIGHEST_SEVERITY", sel_none()), &t, None),
            vec![("HIGHEST_SEVERITY".into(), "255".into())]
        );
        // Sic: WEBAPPID values are named with the (empty) `m_name`.
        assert_eq!(eval(&var("WEBAPPID", sel_none()), &t, None), vec![("".into(), "bisteka".into())]);

        let d = eval(&var("DURATION", sel_none()), &t, None);
        assert_eq!(d[0].0, "DURATION");
        assert!(d[0].1.contains('.') && d[0].1.split('.').nth(1).unwrap().len() == 6);

        let all_digits = |s: &str| !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit());
        for (tok, len) in
            [("TIME_DAY", 2), ("TIME_HOUR", 2), ("TIME_MIN", 2), ("TIME_SEC", 2), ("TIME_WDAY", 1), ("TIME_YEAR", 4)]
        {
            let v = eval(&var(tok, sel_none()), &t, None);
            assert_eq!(v[0].0, tok);
            assert!(all_digits(&v[0].1) && v[0].1.len() == len, "{} {}", tok, v[0].1);
        }
        let mon: i32 = eval(&var("TIME_MON", sel_none()), &t, None)[0].1.parse().unwrap();
        assert!((1..=12).contains(&mon));
        assert!(all_digits(&eval(&var("TIME_EPOCH", sel_none()), &t, None)[0].1));
        let time = &eval(&var("TIME", sel_none()), &t, None)[0];
        assert_eq!(time.0, "TIME");
        assert_eq!(time.1.len(), 8);
        assert_eq!(&time.1[2..3], ":");
    }
}
