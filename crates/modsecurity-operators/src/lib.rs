//! The SecLang operators: `@rx`, `@pm`, `@contains`, `@detectSQLi`,
//! `@ipMatch`, `@rbl`, `@validateSchema`, `@geoLookup`, ... (37 of them).
//!
//! An [`Operator`] is built from its [`Param`] by [`instantiate`], which
//! compiles or loads what the parameter names (files and URLs through
//! [`Resources`]) and fails with a message when it cannot: an operator
//! that exists is ready to be asked whether values match. What it may do
//! while matching is the [`Context`] it is given: read its parameter for
//! the transaction at hand, record captures and match positions, write to
//! the debug log. Nothing here knows about rules or transactions; the
//! ModSecurity engine implements [`Context`] and [`Resources`].
//! (`@inspectFile` is part of the engine: it runs Lua with the
//! transaction.)

#![forbid(unsafe_code)]

use std::borrow::Cow;

pub use modsecurity_types::DebugSink;
pub(crate) use modsecurity_types::ms_dbg;

pub mod begins_with;
mod candidates;
pub mod contains;
pub mod contains_word;
pub mod detect_sqli;
pub mod detect_xss;
pub mod ends_with;
pub mod eq;
pub mod fuzzy_hash;
pub mod ge;
pub mod geo_lookup;
pub mod gsblookup;
pub mod gt;
pub mod ip_match;
pub mod ip_match_from_file;
pub mod ip_set;
pub mod le;
pub mod libinjection_adapter;
pub mod libinjection_utils;
pub mod lt;
mod needle;
pub mod no_match;
pub mod pm;
pub mod pm_from_file;
pub mod rbl;
pub mod rsub;
pub mod rx;
pub mod seclang;
pub mod str_eq;
pub mod str_match;
pub mod unconditional_match;
pub mod validate_byte_range;
pub mod validate_dtd;
pub mod validate_hash;
pub mod validate_schema;
pub mod validate_url_encoding;
pub mod validate_utf8_encoding;
pub mod verify_cc;
pub mod verify_cpf;
pub mod verify_ssn;
pub mod verify_svnr;
pub mod within;

/// The parameter of an operator (`@op parameter`), as the operator keeps
/// it: the text without its macros, and whether it has any. When it does
/// (`%{TX.x}`), the operator gets the parameter expanded for each
/// transaction from its [`Context`].
#[derive(Debug, Default)]
pub struct Param {
    /// The parameter expanded without a transaction (macros left out):
    /// what operators compile or load when the rules are read.
    pub literal: Vec<u8>,
    has_macros: bool,
    /// Whether the match message shows the parameter expanded for the
    /// transaction or the literal.
    expanded_in_message: bool,
}

impl Param {
    /// A parameter whose text without macros is `literal`.
    pub fn new(literal: Vec<u8>, has_macros: bool) -> Self {
        Param { literal, has_macros, expanded_in_message: false }
    }

    /// A parameter without macros.
    pub fn from_text(text: &str) -> Self {
        Param::new(text.as_bytes().to_vec(), false)
    }

    /// The same parameter, shown in match messages with its macros
    /// expanded.
    pub fn expanded_in_message(self) -> Self {
        Param { expanded_in_message: true, ..self }
    }

    pub fn contains_macro(&self) -> bool {
        self.has_macros
    }

    /// Whether match messages show the parameter with its macros expanded.
    pub fn is_expanded_in_message(&self) -> bool {
        self.expanded_in_message
    }

    /// The literal as text, for operators whose parameter is a file name
    /// or similar.
    pub fn literal_lossy(&self) -> String {
        String::from_utf8_lossy(&self.literal).into_owned()
    }
}

pub use seclang::{SecLangOperator, seclang_operator};

/// What an operator may do while it evaluates a value.
pub trait Context: DebugSink {
    /// `param` with its macros expanded for this transaction, borrowed
    /// when it has none.
    fn param<'p>(&self, param: &'p Param) -> Cow<'p, [u8]>;

    /// Whether the rule has the `capture` action.
    fn captures(&self) -> bool;

    /// Stores a captured value as `TX:<group>` (`TX:0` ... `TX:9`); for
    /// rules that capture ([`Self::captures`]).
    fn set_capture(&mut self, group: &[u8], value: Vec<u8>);

    /// Records text the operator matched.
    fn matched(&mut self, value: Vec<u8>);

    /// Records the position of a match in the input.
    fn offset(&mut self, offset: usize, len: usize);

    /// The database of `SecGeoLookupDb`, for `@geoLookup`; `None` when
    /// there is none.
    fn geo_db(&self) -> Option<std::sync::Arc<geo_lookup::GeoDb>>;

    /// Sets `GEO:<name>`, for `@geoLookup`.
    fn set_geo(&mut self, name: &[u8], value: &[u8]);

    /// `SecPcreMatchLimit` (0 when not set).
    fn pcre_match_limit(&self) -> u64;

    /// Reports a regular expression that failed to compile.
    fn regex_compile_error(&mut self, pattern: &str);

    /// Reports a failed regular expression search by `op_name`
    /// (`match_limit`: it hit the match limit).
    fn regex_search_error(&mut self, pattern: &str, match_limit: bool, op_name: &str);

    /// `SecHttpBlKey` (empty when not set), for `@rbl`.
    fn httpbl_key(&self) -> &[u8];

    /// The document the XML request body processor parsed and whether it
    /// is well formed, for `@validateDTD` and
    /// `@validateSchema`; `None` without a document.
    #[cfg(feature = "libxml2")]
    fn xml_document(&self) -> Option<(&modsecurity_native::libxml2::Document, bool)>;
}

/// Where a resource named in a configuration was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceLookup {
    /// The path to open, when the resource was found.
    pub path: Option<String>,
    /// `Looking at: '…', '…'`: the places tried, for error messages.
    pub looked_at: String,
}

/// How operators get the files and URLs their parameters name
/// (`@pmFromFile`, `@ipMatchFromFile`, `@fuzzyHash`).
pub trait Resources {
    /// Looks for `resource` as given and relative to the configuration
    /// file `config`.
    fn find(&self, resource: &str, config: &str) -> ResourceLookup;

    /// Downloads `url` (`https://...`); the error is the message to
    /// report.
    fn download(&self, url: &str) -> Result<Vec<u8>, String>;
}

/// A SecRule operator (`@rx`, `@pm`, ...).
pub trait Operator: Send + Sync + std::fmt::Debug {
    /// The operator name shown in match messages and the debug log (e.g.
    /// `Rx`).
    fn name(&self) -> &'static str;

    /// The parameter, for operators that take one.
    fn param(&self) -> Option<&Param> {
        None
    }

    /// Whether `input` matches (before the negation of `!@op`).
    fn evaluate(&self, cx: &mut dyn Context, input: &[u8]) -> bool;

    /// The result of the rule's operator: [`Operator::evaluate`] with the
    /// negation of `!@op` applied. Operators whose failures must not match
    /// even when negated override this.
    fn evaluate_negatable(&self, negated: bool, cx: &mut dyn Context, input: &[u8]) -> bool {
        self.evaluate(cx, input) != negated
    }

    /// The text logged for a match of `value` in the variable `key`;
    /// `param` is the parameter as the message shows it.
    fn resolve_match_message(&self, param: &[u8], key: &[u8], value: &[u8]) -> Vec<u8> {
        match_message(self.name(), param, key, value)
    }
}

/// The usual match message of an operator called `name`.
pub fn match_message(name: &str, param: &[u8], key: &[u8], value: &[u8]) -> Vec<u8> {
    use modsecurity_compat::chars::{limit_to, to_hex_if_needed};
    let mut ret = Vec::new();
    ret.extend_from_slice(b"Matched \"Operator `");
    ret.extend_from_slice(name.as_bytes());
    ret.extend_from_slice(b"' with parameter `");
    ret.extend_from_slice(&limit_to(200, param));
    ret.extend_from_slice(b"' against variable `");
    ret.extend_from_slice(to_hex_if_needed(key, false).as_bytes());
    ret.extend_from_slice(b"' (Value: `");
    ret.extend_from_slice(&limit_to(100, to_hex_if_needed(value, false).as_bytes()));
    ret.extend_from_slice(b"' )");
    ret
}

/// Builds the operator named `name` (case insensitive, without the `@`)
/// with the parameter `param`, compiling or loading what the parameter
/// names; `file` is the configuration file of the rule. `None` when it is
/// not one of this crate's, `Some(Err(message))` when it cannot be built.
pub fn instantiate(
    name: &str,
    param: Param,
    file: &str,
    resources: &dyn Resources,
) -> Option<Result<Box<dyn Operator>, String>> {
    /// An operator that cannot fail to be built.
    fn ready(op: impl Operator + 'static) -> Result<Box<dyn Operator>, String> {
        Ok(Box::new(op))
    }
    /// An operator that compiles or loads something to be built.
    fn built(op: Result<impl Operator + 'static, String>) -> Result<Box<dyn Operator>, String> {
        op.map(|op| Box::new(op) as Box<dyn Operator>)
    }
    Some(match name.to_ascii_lowercase().as_str() {
        "beginswith" => ready(begins_with::BeginsWith::new(param)),
        "contains" => ready(contains::Contains::new(param)),
        "containsword" => ready(contains_word::ContainsWord::new(param)),
        "detectsqli" => ready(detect_sqli::DetectSQLi::new()),
        "detectxss" => ready(detect_xss::DetectXSS::new()),
        "endswith" => ready(ends_with::EndsWith::new(param)),
        "eq" => ready(eq::Eq::new(param)),
        "fuzzyhash" => built(fuzzy_hash::FuzzyHash::new(param, file, resources)),
        "ge" => ready(ge::Ge::new(param)),
        "geolookup" => ready(geo_lookup::GeoLookup::new()),
        "gsblookup" => ready(gsblookup::GsbLookup::new(param)),
        "gt" => ready(gt::Gt::new(param)),
        "ipmatch" => built(ip_match::IpMatch::new(param)),
        "ipmatchf" | "ipmatchfromfile" => built(ip_match_from_file::IpMatchFromFile::new(param, file, resources)),
        "le" => ready(le::Le::new(param)),
        "lt" => ready(lt::Lt::new(param)),
        "nomatch" => ready(no_match::NoMatch::new()),
        "pm" => built(pm::Pm::new(param)),
        "pmf" => built(pm_from_file::PmFromFile::with_name("PmFromF", param, file, resources)),
        "pmfromfile" => built(pm_from_file::PmFromFile::new(param, file, resources)),
        "rbl" => ready(rbl::Rbl::new(param)),
        "rsub" => ready(rsub::Rsub::new(param)),
        "rx" => built(rx::Rx::new(param)),
        "rxglobal" => built(rx::Rx::global(param)),
        "streq" => ready(str_eq::StrEq::new(param)),
        "strmatch" => ready(str_match::StrMatch::new(param)),
        "unconditionalmatch" => ready(unconditional_match::UnconditionalMatch::new()),
        "validatebyterange" => built(validate_byte_range::ValidateByteRange::new(param)),
        "validatedtd" => built(validate_dtd::ValidateDTD::new(param, file, resources)),
        "validatehash" => ready(validate_hash::ValidateHash::new(param)),
        "validateschema" => built(validate_schema::ValidateSchema::new(param, file, resources)),
        "validateurlencoding" => ready(validate_url_encoding::ValidateUrlEncoding::new()),
        "validateutf8encoding" => ready(validate_utf8_encoding::ValidateUtf8Encoding::new()),
        "verifycc" => built(verify_cc::VerifyCC::new(param)),
        "verifycpf" => built(verify_cpf::VerifyCPF::new(param)),
        "verifyssn" => built(verify_ssn::VerifySSN::new(param)),
        "verifysvnr" => built(verify_svnr::VerifySVNR::new(param)),
        "within" => ready(within::Within::new(param)),
        _ => return None,
    })
}

/// Evaluating operators in tests, against a context that records nothing.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// A context for a rule that captures, without macros or debug log.
    #[derive(Default)]
    pub struct TestContext {
        pub captures: Vec<(Vec<u8>, Vec<u8>)>,
        pub matched: Vec<Vec<u8>>,
        pub offsets: Vec<(usize, usize)>,
        pub httpbl_key: Vec<u8>,
        pub geo_db: Option<std::sync::Arc<geo_lookup::GeoDb>>,
        /// The `GEO` entries set.
        pub geo: Vec<(Vec<u8>, Vec<u8>)>,
    }

    impl DebugSink for TestContext {
        fn debug_enabled(&self, _level: u8) -> bool {
            false
        }
        fn debug(&self, _level: u8, _message: &str) {}
    }

    impl Context for TestContext {
        fn param<'p>(&self, param: &'p Param) -> Cow<'p, [u8]> {
            Cow::Borrowed(&param.literal)
        }
        fn captures(&self) -> bool {
            true
        }
        fn set_capture(&mut self, group: &[u8], value: Vec<u8>) {
            self.captures.push((group.to_vec(), value));
        }
        fn matched(&mut self, value: Vec<u8>) {
            self.matched.push(value);
        }
        fn offset(&mut self, offset: usize, len: usize) {
            self.offsets.push((offset, len));
        }
        fn geo_db(&self) -> Option<std::sync::Arc<geo_lookup::GeoDb>> {
            self.geo_db.clone()
        }
        fn set_geo(&mut self, name: &[u8], value: &[u8]) {
            self.geo.push((name.to_vec(), value.to_vec()));
        }
        fn pcre_match_limit(&self) -> u64 {
            0
        }
        fn regex_compile_error(&mut self, _pattern: &str) {}
        fn regex_search_error(&mut self, _pattern: &str, _match_limit: bool, _op_name: &str) {}
        fn httpbl_key(&self) -> &[u8] {
            &self.httpbl_key
        }
        #[cfg(feature = "libxml2")]
        fn xml_document(&self) -> Option<(&modsecurity_native::libxml2::Document, bool)> {
            None
        }
    }

    /// Resources of the local file system: names as given, then relative to
    /// the directory of the configuration file. No downloads.
    pub struct LocalFiles;

    impl Resources for LocalFiles {
        fn find(&self, resource: &str, config: &str) -> ResourceLookup {
            let dir = config.rfind('/').map_or("", |i| &config[..i]);
            let relative = format!("{dir}/{resource}");
            for candidate in [resource, relative.as_str()] {
                if std::fs::File::open(candidate).is_ok() {
                    return ResourceLookup { path: Some(candidate.to_string()), looked_at: String::new() };
                }
            }
            ResourceLookup { path: None, looked_at: format!("Looking at: '{resource}', '{relative}'.") }
        }
        fn download(&self, url: &str) -> Result<Vec<u8>, String> {
            Err(format!("no downloads in tests: {url}"))
        }
    }

    /// `op` applied to `input`.
    pub fn eval(op: &dyn Operator, input: &[u8]) -> bool {
        op.evaluate(&mut TestContext::default(), input)
    }
}
