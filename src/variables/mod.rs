//! `variables`: the targets of rules.
//!
//! [`variable::Variable`] is a target; [`new_variable`] builds it from its
//! name in the rule. The variables that only read a value of the
//! transaction are rows of the tables in `names`, which
//! [`new_variable`] looks up first.
//! The variables with logic of their own have a module:
//! the collections ([`persistent`], and `TX` in [`variable`]), [`rule`],
//! [`env`], [`xml`] and the [`computed`] ones (`TIME*`, `DURATION`, ...).

pub mod anchored_set_variable;
pub mod anchored_set_variable_translation_proxy;
pub mod anchored_variable;
pub(crate) mod computed;
pub mod env;
pub(crate) mod names;
pub mod persistent;
pub mod rule;
pub mod variable;
pub mod xml;

/// The resolved values and their origin (the `modsecurity-types` crate).
pub(crate) use modsecurity_types::{variable_origin, variable_value};

use modsecurity_native::regex::Regex;
use variable::{CollectionKey, Source, Variable, regex_name};

/// How a variable is selected in a rule target: `ARGS`, `ARGS:foo`,
/// `ARGS:/regex/` or, for the collections that accept it, a key built from
/// macros (`TX:%{...}`).
#[derive(Debug)]
pub enum VariableSelector {
    None,
    DictElement(String),
    Regexp(String),
    Dynamic(crate::run_time_string::RunTimeString),
}

/// Why [`new_variable`] gives no variable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VariableError {
    /// No variable has the name, or it does not accept the selector.
    Unknown,
    /// The regular expression of a `COLLECTION:/regex/` selector does not
    /// compile: the pattern.
    InvalidRegex(String),
}

impl std::fmt::Display for VariableError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VariableError::Unknown => f.write_str("Unknown variable"),
            VariableError::InvalidRegex(pattern) => write!(f, "Invalid regular expression: {pattern}"),
        }
    }
}

impl std::error::Error for VariableError {}

/// Compiles the regex of a `COLLECTION:/regex/` selector: case
/// insensitive, multi-line.
pub(crate) fn selector_regex(pattern: &str) -> Result<Regex, VariableError> {
    Regex::compile(pattern.as_bytes(), true, true).map_err(|_| VariableError::InvalidRegex(pattern.to_string()))
}

/// Creates the variable named `name` with the given
/// selector. Fails with [`VariableError::Unknown`] for unknown names and
/// for selectors a variable does not accept (e.g.
/// `REQUEST_METHOD:foo`, `ARGS:%{...}`) and for `WEBSERVER_ERROR_LOG`,
/// and with [`VariableError::InvalidRegex`] for a regex selector that does
/// not compile; the parser reports these as
/// errors. The `!` / `&` modifiers are applied by the caller.
///
/// `name` is matched case insensitively.
/// The computed variables (`DURATION`, `MODSEC_BUILD`,
/// `HIGHEST_SEVERITY`, `REMOTE_USER`, `TIME*`) are named
/// with the text as written in the rule, so `name` is
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
/// (The `ENV:/regex/` and `XML:/regex/` forms are not regular
/// expressions: the text between the slashes is used as the key.)
pub fn new_variable(name: &str, selector: VariableSelector) -> Result<Variable, VariableError> {
    use VariableSelector as S;
    use computed::Computed as C;
    use persistent::Persistent;

    // A computed variable, named after the text as written in the
    // rule.
    let computed = |selector: VariableSelector, c: C| match selector {
        S::None => Ok(Variable::new(name, Source::Computed(c))),
        _ => Err(VariableError::Unknown),
    };

    let token = name.to_ascii_uppercase();
    // The variables of the transaction (the shared table).
    if let Some(v) = names::SETS.iter().find(|v| v.token == token) {
        let (name, selector) = Variable::selected(v.token, selector)?;
        return Ok(Variable::new(&name, Source::Set(v.get, selector)));
    }
    if let Some(v) = names::NAMES.iter().find(|v| v.token == token) {
        let (name, selector) = Variable::selected(v.token, selector)?;
        return Ok(Variable::new(&name, Source::Names(v.get, selector)));
    }
    if let Some(v) = names::SINGLE.iter().find(|v| v.seclang && v.token == token) {
        return match selector {
            S::None => Ok(Variable::new(v.name, Source::Single(v.get))),
            _ => Err(VariableError::Unknown),
        };
    }
    if let Some(collection) = Persistent::parse(token.as_bytes()) {
        return persistent::variable(collection, selector);
    }
    match token.as_str() {
        "RULE" => {
            let (name, selector) = Variable::selected(rule::RULE, selector)?;
            Ok(Variable::new(&name, Source::Rule(selector)))
        }

        "TX" => {
            let (name, key) = match selector {
                S::None => ("TX".to_string(), CollectionKey::All),
                S::DictElement(e) => (format!("TX:{}", e), CollectionKey::Key),
                S::Regexp(r) => (regex_name("TX", &r), CollectionKey::Regex(selector_regex(&r)?)),
                S::Dynamic(m) => ("TX:dynamic".to_string(), CollectionKey::Dynamic(m)),
            };
            Ok(Variable::new(&name, Source::Tx(key)))
        }

        // `ENV` and `XML`: a regex selector is taken as a key.
        "ENV" => match selector {
            S::None => Ok(Variable::new("ENV", Source::Env)),
            S::DictElement(e) | S::Regexp(e) => Ok(Variable::new(&format!("ENV:{}", e), Source::Env)),
            S::Dynamic(_) => Err(VariableError::Unknown),
        },
        "XML" => match selector {
            S::None => Ok(Variable::new("XML", Source::XmlDocument)),
            S::DictElement(e) | S::Regexp(e) => Ok(Variable::new(&format!("XML:{}", e), Source::XmlPath)),
            S::Dynamic(_) => Err(VariableError::Unknown),
        },

        "WEBAPPID" => match selector {
            S::None => Ok(Variable::new("WEBAPPID", Source::Computed(C::WebAppId))),
            _ => Err(VariableError::Unknown),
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

        // `WEBSERVER_ERROR_LOG` is rejected by the parser ("not
        // supported by libModSecurity"); anything else is unknown.
        _ => Err(VariableError::Unknown),
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
        fn write(&self, level: u8, msg: &str) {
            self.log.lock().unwrap().push_str(&format!("[{}] {}\n", level, msg));
        }
        fn write_ctx(&self, level: u8, _id: &str, _uri: &str, msg: &str) {
            self.write(level, msg);
        }
        fn level(&self) -> Option<u8> {
            Some(9)
        }
        fn set_level(&mut self, _level: u8) {}
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
    use crate::instance::ModSecurity;
    use crate::rule::{Rule, RuleKind};
    use crate::rules_set::RulesSet;
    use crate::run_time_string::RunTimeString;
    use crate::transaction::Transaction;
    use crate::variables::variable_value::VariableValue;

    fn eval(v: &Variable, t: &Transaction<'_>, rule: Option<&Rule>) -> Vec<(String, String)> {
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
        new_variable(token, sel).unwrap_or_else(|e| panic!("no variable for {}: {e}", token))
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
    /// (token, name of the variable)
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
            assert!(new_variable(n, sel_dyn("x")).is_err(), "{}", n);
            // Case insensitive token.
            assert!(new_variable(&n.to_lowercase(), sel_none()).is_ok());
        }
    }

    #[test]
    fn factory_collections() {
        for &n in COLLECTIONS {
            let v = var(n, sel_none());
            assert_eq!(v.full_name(), n);
            assert!(v.write_target().is_none());
            let v = var(n, sel_key("foo"));
            assert_eq!(v.full_name(), format!("{}:foo", n));
            let v = var(n, sel_re("^f"));
            assert_eq!(v.regex().map(|r| r.pattern.as_str()), Some("^f"));
            let expected = if n == "RESOURCE" { "RESOURCE::regex(^f)".to_string() } else { format!("{}:regex(^f)", n) };
            assert_eq!(v.full_name(), expected);
            let v = var(n, sel_dyn("x"));
            assert_eq!(v.full_name(), format!("{}:dynamic", n));
            assert!(v.write_target().is_some());
        }
    }

    #[test]
    fn factory_single_and_runtime_variables() {
        for &(token, name) in SINGLES {
            let v = var(token, sel_none());
            assert_eq!(v.full_name(), name, "{}", token);
            assert!(new_variable(token, sel_key("x")).is_err(), "{}", token);
            assert!(new_variable(token, sel_re("x")).is_err(), "{}", token);
            assert!(new_variable(token, sel_dyn("x")).is_err(), "{}", token);
        }
        // The computed variables: named after the text as written.
        assert_eq!(var("time_hour", sel_none()).full_name(), "time_hour");
        // ENV and XML.
        assert_eq!(var("ENV", sel_none()).full_name(), "ENV");
        assert_eq!(var("ENV", sel_key("PATH")).full_name(), "ENV:PATH");
        assert_eq!(var("ENV", sel_re("PA")).full_name(), "ENV:PA");
        assert!(new_variable("ENV", sel_dyn("x")).is_err());
        assert_eq!(var("XML", sel_none()).full_name(), "XML");
        assert_eq!(var("XML", sel_key("/a/b")).full_name(), "XML:/a/b");
        assert!(new_variable("XML", sel_dyn("x")).is_err());
        // Unknown / unsupported.
        assert!(new_variable("WEBSERVER_ERROR_LOG", sel_none()).is_err());
        assert!(new_variable("NOT_A_VARIABLE", sel_none()).is_err());
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
        let mut t = Transaction::new(&ms, &rules, None);
        let dynamic = var("TX", sel_dyn("score"));
        dynamic.write_target().unwrap().store(&mut t, b"score", b"5".to_vec());
        dynamic.write_target().unwrap().store(&mut t, b"other", b"7".to_vec());

        assert_eq!(eval(&var("TX", sel_key("score")), &t, None), vec![("TX:score".into(), "5".into())]);
        // The backend names the value with the requested key.
        assert_eq!(eval(&var("TX", sel_key("SCORE")), &t, None), vec![("TX:SCORE".into(), "5".into())]);
        assert_eq!(eval(&dynamic, &t, None), vec![("TX:score".into(), "5".into())]);
        assert_eq!(eval(&var("TX", sel_re("^oth")), &t, None), vec![("TX:other".into(), "7".into())]);
        let mut all = eval(&var("TX", sel_none()), &t, None);
        all.sort();
        assert_eq!(all, vec![("TX:other".into(), "7".into()), ("TX:score".into(), "5".into())]);

        dynamic.write_target().unwrap().remove(&mut t, b"score");
        assert!(eval(&var("TX", sel_key("score")), &t, None).is_empty());
    }

    #[test]
    fn persistent_collections_are_compartmentalised() {
        let ms = ModSecurity::new();
        let (mut rules, _log) = rules_with_log();
        rules.properties.settings.sec_web_app_id = Some("app".to_string());
        let mut t = Transaction::new(&ms, &rules, None);
        // The persistent collections may live on disk (LMDB): use keys
        // unique to this run.
        let nonce = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        );
        let ip_key = format!("ip-{}", nonce);
        t.collections.ip.key = ip_key.as_bytes().to_vec();
        t.collections.global.key = format!("global-{}", nonce).into_bytes();
        t.collections.session.key = format!("sess-{}", nonce).into_bytes();
        t.collections.user.key = format!("user-{}", nonce).into_bytes();
        t.collections.resource.key = format!("res-{}", nonce).into_bytes();

        for c in ["IP", "GLOBAL", "SESSION", "USER", "RESOURCE"] {
            let d = var(c, sel_dyn("zz"));
            d.write_target().unwrap().store(&mut t, b"key1", b"v1".to_vec());
            let got = eval(&var(c, sel_key("key1")), &t, None);
            assert_eq!(got.len(), 1, "{}", c);
            assert_eq!(got[0].1, "v1", "{}", c);
            assert_eq!(eval(&d, &t, None).len(), 0, "{} (dynamic name `zz`)", c);
        }
        // The stored key carries the collection key and the web app id.
        assert_eq!(
            ms.ip_collection.resolve_first(format!("{}::app::key1", ip_key).as_bytes()),
            Ok(Some(b"v1".to_vec()))
        );

        // IP del uses the same compartments.
        var("IP", sel_dyn("key1")).write_target().unwrap().remove(&mut t, b"key1");
        assert!(eval(&var("IP", sel_key("key1")), &t, None).is_empty());
        // SESSION too. (C++ deletes under the key of the IP collection
        // instead of the web application's, which removes nothing.)
        var("SESSION", sel_dyn("key1")).write_target().unwrap().remove(&mut t, b"key1");
        assert!(eval(&var("SESSION", sel_key("key1")), &t, None).is_empty());
    }

    #[test]
    fn rule_variable_walks_the_chain() {
        let ms = ModSecurity::new();
        let rules = RulesSet::new();
        let mut parent = Rule::new(None, None, "f", 1, RuleKind::SecAction);
        parent.rule_id = 10;
        parent.rev = "3".to_string();
        let sev = crate::actions::severity::Severity::new("severity", "2").unwrap();
        let mut child = Rule::new(
            Some(vec![crate::actions::rule_action::RuleAction::Severity(sev)]),
            None,
            "f",
            2,
            RuleKind::SecAction,
        );
        child.rule_id = crate::rule::Id::default();
        parent.chained_rule_child = Some(Box::new(child));
        let child = parent.chained_rule_child.as_deref().unwrap();

        let mut t = Transaction::new(&ms, &rules, None);
        // Outside of the chain evaluation the child has no parent.
        assert!(eval(&var("RULE", sel_key("id")), &t, Some(child)).is_empty());

        t.eval.chained_rule_parents.push(&parent);
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
        // A variable of the process: cargo sets this one for tests.
        let (process_name, process_value) = ("CARGO_PKG_NAME", env!("CARGO_PKG_NAME"));

        assert_eq!(eval(&var("ENV", sel_key("modfoo")), &t, None), vec![("ENV:modfoo".into(), "bar".into())]);
        assert!(eval(&var("ENV", sel_key("MODFOO")), &t, None).is_empty());
        assert_eq!(
            eval(&var("ENV", sel_key(process_name)), &t, None),
            vec![(format!("ENV:{process_name}"), process_value.to_string())]
        );
        let all = eval(&var("ENV", sel_none()), &t, None);
        assert!(all.contains(&("ENV:modfoo".into(), "bar".into())));
        assert!(all.contains(&(format!("ENV:{process_name}"), process_value.to_string())));
        // setenv wins over the process environment.
        t.variable_envs.insert(process_name.as_bytes().to_vec(), b"mine".to_vec());
        assert_eq!(eval(&var("ENV", sel_key(process_name)), &t, None)[0].1, "mine");
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
        rules.properties.settings.sec_web_app_id = Some("bisteka".to_string());
        let t = Transaction::new(&ms, &rules, None);

        assert_eq!(eval(&var("MODSEC_BUILD", sel_none()), &t, None), vec![("MODSEC_BUILD".into(), "030017100".into())]);
        assert_eq!(
            eval(&var("HIGHEST_SEVERITY", sel_none()), &t, None),
            vec![("HIGHEST_SEVERITY".into(), "255".into())]
        );
        // Sic: WEBAPPID values have an empty name.
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

    /// A regex selector that does not compile refuses the configuration,
    /// in every place a selector is written. (Such a regex used to match
    /// nothing: `SecRule ARGS:/(/ ...` loaded and inspected no value.)
    #[test]
    fn invalid_selector_regexes_refuse_the_configuration() {
        let refused = |conf: &str| {
            let mut rules = RulesSet::new();
            let error = rules.load(conf).expect_err(conf);
            assert!(error.message().contains("Invalid regular expression: ("), "{conf}: {error}");
        };
        for target in
            ["ARGS:/(/", "ARGS_NAMES:/(/", "REQUEST_HEADERS:/(/", "RULE:/(/", "TX:/(/", "IP:/(/", "ARGS|!ARGS:/(/"]
        {
            refused(&format!("SecRule {target} \"@rx x\" \"id:1,phase:1,pass\""));
        }
        refused("SecRule ARGS \"@rx x\" \"id:1,phase:1,pass,msg:'%{ARGS:/(/}'\"");
        refused("SecRule ARGS \"@rx x\" \"id:1,phase:1,pass\"\nSecRuleUpdateTargetById 1 \"!ARGS:/(/\"");
        refused("SecAuditLogRelevantStatus \"(\"");

        // Valid ones load; ENV and XML take the text between the slashes as a key.
        let mut rules = RulesSet::new();
        rules.load("SecRule ARGS:/^a(b)?$/|!ARGS:/c+/|ENV:/(/|XML:/(/ \"@rx x\" \"id:1,phase:1,pass\"").unwrap();
        assert_eq!(new_variable("ARGS", sel_re("(")).unwrap_err(), VariableError::InvalidRegex("(".into()));
    }
}
