//! The SecLang operators that only match: `@rx`, `@pm`, `@contains`,
//! `@detectSQLi`, `@ipMatch`, `@rbl`, `@validateSchema`, ... (36 of them).
//!
//! An [`Operator`] is built from its [`Param`] by [`instantiate`], prepared
//! once with [`Operator::init`] (which may load files through
//! [`Resources`]), and then asked whether values match. What it may do
//! while matching is the [`Context`] it is given: read its parameter for
//! the transaction at hand, record captures and match positions, write to
//! the debug log. Nothing here knows about rules or transactions; the
//! ModSecurity engine implements [`Context`] and [`Resources`]. (`@geoLookup`
//! and `@inspectFile` are part of the engine: they fill the `GEO`
//! collection and run Lua with the transaction.)

#![forbid(unsafe_code)]

use std::borrow::Cow;

/// Writes to the debug log through a [`Context`]: the message is only
/// formatted when the debug level is high enough.
macro_rules! op_dbg {
    ($cx:expr, $lvl:expr, $($arg:tt)*) => {{
        if $cx.debug_enabled($lvl) {
            $cx.debug($lvl, &format!($($arg)*));
        }
    }};
}
pub(crate) use op_dbg;

pub mod begins_with;
pub mod contains;
pub mod contains_word;
pub mod detect_sqli;
pub mod detect_xss;
pub mod ends_with;
pub mod eq;
pub mod fuzzy_hash;
pub mod ge;
pub mod gsblookup;
pub mod gt;
pub mod ip_match;
pub mod ip_match_from_file;
pub mod ip_tree;
pub mod le;
pub mod libinjection_adapter;
pub mod libinjection_utils;
pub mod lt;
pub mod no_match;
pub mod pm;
pub mod pm_from_file;
pub mod rbl;
pub mod rsub;
pub mod rx;
pub mod rx_global;
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

/// What an operator may do while it evaluates a value.
pub trait Context {
    /// Whether the debug log takes messages of `level`.
    fn debug_enabled(&self, level: i32) -> bool;

    /// Writes `message` to the debug log.
    fn debug(&self, level: i32, message: &str);

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

    /// `SecPcreMatchLimit` (0 when not set).
    fn pcre_match_limit(&self) -> u64;

    /// Reports a regular expression that failed to compile.
    fn regex_compile_error(&mut self, pattern: &str);

    /// Reports a failed regular expression search by `op_name`
    /// (`match_limit`: it hit the match limit).
    fn regex_search_error(&mut self, pattern: &str, match_limit: bool, op_name: &str);

    /// `SecHttpBlKey` (empty when not set), for `@rbl`.
    fn httpbl_key(&self) -> &[u8];

    /// The document the XML request body processor parsed and its
    /// well-formedness flag (1 when well formed), for `@validateDTD` and
    /// `@validateSchema`; `None` without a document.
    #[cfg(feature = "libxml2")]
    fn xml_document(&self) -> Option<(&modsecurity_native::libxml2::Document, u32)>;
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

    /// Compiles or loads what the parameter names, when the rule is read;
    /// `file` is the configuration file of the rule.
    fn init(&mut self, _file: &str, _resources: &dyn Resources) -> Result<(), String> {
        Ok(())
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

/// The operator named `name` (case insensitive, without the `@`) with the
/// parameter `param`; `None` when it is not one of this crate's.
pub fn instantiate(name: &str, param: Param) -> Option<Box<dyn Operator>> {
    let b: Box<dyn Operator> = match name.to_ascii_lowercase().as_str() {
        "beginswith" => Box::new(begins_with::BeginsWith::new(param)),
        "contains" => Box::new(contains::Contains::new(param)),
        "containsword" => Box::new(contains_word::ContainsWord::new(param)),
        "detectsqli" => Box::new(detect_sqli::DetectSQLi::new()),
        "detectxss" => Box::new(detect_xss::DetectXSS::new()),
        "endswith" => Box::new(ends_with::EndsWith::new(param)),
        "eq" => Box::new(eq::Eq::new(param)),
        "fuzzyhash" => Box::new(fuzzy_hash::FuzzyHash::new(param)),
        "ge" => Box::new(ge::Ge::new(param)),
        "gsblookup" => Box::new(gsblookup::GsbLookup::new(param)),
        "gt" => Box::new(gt::Gt::new(param)),
        "ipmatch" => Box::new(ip_match::IpMatch::new(param)),
        "ipmatchf" | "ipmatchfromfile" => Box::new(ip_match_from_file::IpMatchFromFile::new(param)),
        "le" => Box::new(le::Le::new(param)),
        "lt" => Box::new(lt::Lt::new(param)),
        "nomatch" => Box::new(no_match::NoMatch::new()),
        "pm" => Box::new(pm::Pm::new(param)),
        "pmf" => Box::new(pm_from_file::PmFromFile::with_name("PmFromF", param)),
        "pmfromfile" => Box::new(pm_from_file::PmFromFile::new(param)),
        "rbl" => Box::new(rbl::Rbl::new(param)),
        "rsub" => Box::new(rsub::Rsub::new(param)),
        "rx" => Box::new(rx::Rx::new(param)),
        "rxglobal" => Box::new(rx_global::RxGlobal::new(param)),
        "streq" => Box::new(str_eq::StrEq::new(param)),
        "strmatch" => Box::new(str_match::StrMatch::new(param)),
        "unconditionalmatch" => Box::new(unconditional_match::UnconditionalMatch::new()),
        "validatebyterange" => Box::new(validate_byte_range::ValidateByteRange::new(param)),
        "validatedtd" => Box::new(validate_dtd::ValidateDTD::new(param)),
        "validatehash" => Box::new(validate_hash::ValidateHash::new(param)),
        "validateschema" => Box::new(validate_schema::ValidateSchema::new(param)),
        "validateurlencoding" => Box::new(validate_url_encoding::ValidateUrlEncoding::new()),
        "validateutf8encoding" => Box::new(validate_utf8_encoding::ValidateUtf8Encoding::new()),
        "verifycc" => Box::new(verify_cc::VerifyCC::new(param)),
        "verifycpf" => Box::new(verify_cpf::VerifyCPF::new(param)),
        "verifyssn" => Box::new(verify_ssn::VerifySSN::new(param)),
        "verifysvnr" => Box::new(verify_svnr::VerifySVNR::new(param)),
        "within" => Box::new(within::Within::new(param)),
        _ => return None,
    };
    Some(b)
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
    }

    impl Context for TestContext {
        fn debug_enabled(&self, _level: i32) -> bool {
            false
        }
        fn debug(&self, _level: i32, _message: &str) {}
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
        fn pcre_match_limit(&self) -> u64 {
            0
        }
        fn regex_compile_error(&mut self, _pattern: &str) {}
        fn regex_search_error(&mut self, _pattern: &str, _match_limit: bool, _op_name: &str) {}
        fn httpbl_key(&self) -> &[u8] {
            &self.httpbl_key
        }
        #[cfg(feature = "libxml2")]
        fn xml_document(&self) -> Option<(&modsecurity_native::libxml2::Document, u32)> {
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
