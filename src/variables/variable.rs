//! Port of `src/variables/variable.h` / `src/variables/variable.cc`.
//!
//! `Variable` is the base of every SecRule target (`ARGS`, `TX:foo`,
//! `&ARGS`, `!ARGS:id`, ...). The C++ class hierarchy becomes the
//! [`Variable`] trait plus the shared state in [`VariableBase`]; the
//! `DEFINE_VARIABLE*` macros become the `macro_rules!` of the same names.

use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;
use crate::utils::regex::Regex;
use crate::utils::string::toupper_str;
use crate::variable_value::VariableValue;

// ---------------------------------------------------------------------------
// Key exclusions (`!ARGS:foo`, `!ARGS:/regex/`)
// ---------------------------------------------------------------------------

/// `KeyExclusion` and its two implementations.
#[derive(Debug)]
pub enum KeyExclusion {
    /// `KeyExclusionRegex`
    Regex(Regex),
    /// `KeyExclusionString`: stored upper case, compared case insensitively.
    String(Vec<u8>),
}

impl KeyExclusion {
    pub fn regex(re: &str) -> Self {
        KeyExclusion::Regex(Regex::new_case(re, true))
    }

    pub fn string(a: &str) -> Self {
        KeyExclusion::String(a.as_bytes().to_ascii_uppercase())
    }

    pub fn matches(&self, a: &[u8]) -> bool {
        match self {
            KeyExclusion::Regex(r) => r.search(a) > 0,
            KeyExclusion::String(k) => a.len() == k.len() && a.iter().zip(k).all(|(x, y)| x.to_ascii_uppercase() == *y),
        }
    }
}

/// `KeyExclusions`
#[derive(Debug, Default)]
pub struct KeyExclusions(pub Vec<KeyExclusion>);

impl KeyExclusions {
    pub fn new() -> Self {
        KeyExclusions(Vec::new())
    }

    /// `toOmit`
    pub fn to_omit(&self, a: &[u8]) -> bool {
        self.0.iter().any(|z| z.matches(a))
    }

    pub fn push(&mut self, k: KeyExclusion) {
        self.0.push(k);
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Variable
// ---------------------------------------------------------------------------

/// The data members of the C++ `Variable` base class.
#[derive(Debug, Default)]
pub struct VariableBase {
    pub name: String,
    pub collection_name: String,
    pub full_name: String,
    pub key_exclusion: KeyExclusions,
}

impl VariableBase {
    /// `Variable(const std::string &name)`: splits `COLLECTION:name` (or
    /// `COLLECTION.name`).
    pub fn new(name: &str) -> Self {
        let mut b = VariableBase { name: name.to_string(), ..Default::default() };
        let a = name.find(':').or_else(|| name.find('.'));
        match a {
            Some(a) => {
                b.collection_name = toupper_str(&name[..a]);
                b.name = name[a + 1..].to_string();
                b.full_name = format!("{}:{}", b.collection_name, b.name);
            }
            None => {
                b.full_name = name.to_string();
                b.collection_name = name.to_string();
                b.name = String::new();
            }
        }
        b
    }

    /// `Variable(const Variable *_name)` (key exclusions are not copied).
    pub fn copy_of(v: &VariableBase) -> Self {
        VariableBase {
            name: v.name.clone(),
            collection_name: v.collection_name.clone(),
            full_name: v.full_name.clone(),
            key_exclusion: KeyExclusions::new(),
        }
    }
}

/// A SecRule target.
pub trait Variable: Send + Sync + std::fmt::Debug {
    fn base(&self) -> &VariableBase;
    fn base_mut(&mut self) -> &mut VariableBase;

    /// Resolves the variable for `t`, appending the values to `l`.
    fn evaluate(&self, t: &Transaction<'_>, rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>);

    /// `dynamic_cast<VariableRegex *>`: the selection regex, if this is a
    /// `COLLECTION:/regex/` variable.
    fn regex(&self) -> Option<&Regex> {
        None
    }

    /// `VariableRegex::m_regex` (the pattern text).
    fn regex_pattern(&self) -> Option<&str> {
        self.regex().map(|r| r.pattern.as_str())
    }

    /// `dynamic_cast<VariableModificatorExclusion *>`: the excluded variable.
    fn exclusion_base(&self) -> Option<&dyn Variable> {
        None
    }

    /// `X_DynamicElement::m_string`: for the `TX:%{...}`-style variables
    /// of the persistent and TX collections, the macro that names the key.
    /// (The C++ `SetVar` action `dynamic_cast`s to the six
    /// `*_DynamicElement` classes; these three methods replace that.)
    fn dynamic_name(&self) -> Option<&crate::run_time_string::RunTimeString> {
        None
    }

    /// `X_DynamicElement::del(t, k)`
    fn dynamic_del(&self, _t: &Transaction<'_>, _key: &[u8]) {}

    /// `X_DynamicElement::storeOrUpdateFirst(t, var, value)`
    fn dynamic_store_or_update_first(&self, _t: &Transaction<'_>, _key: &[u8], _value: &[u8]) {}

    fn name(&self) -> &str {
        &self.base().name
    }

    fn collection_name(&self) -> &str {
        &self.base().collection_name
    }

    fn full_name(&self) -> &str {
        &self.base().full_name
    }

    fn key_exclusion(&self) -> &KeyExclusions {
        &self.base().key_exclusion
    }
}

impl dyn Variable + '_ {
    /// `belongsToCollection`
    pub fn belongs_to_collection(&self, var: &dyn Variable) -> bool {
        let a = self.collection_name().as_bytes();
        let b = var.collection_name().as_bytes();
        a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.to_ascii_uppercase() == *y)
    }

    /// `addsKeyExclusion`: if `v` is an exclusion (`!ARGS:foo`), record its
    /// key (or regex) as excluded from this variable.
    pub fn adds_key_exclusion(&mut self, v: &dyn Variable) {
        let Some(base) = v.exclusion_base() else {
            return;
        };
        let r = match base.regex_pattern() {
            None => KeyExclusion::string(v.name()),
            Some(re) => KeyExclusion::regex(re),
        };
        self.base_mut().key_exclusion.push(r);
    }

    /// `operator==`
    pub fn same_as(&self, b: &dyn Variable) -> bool {
        self.collection_name() == b.collection_name() && self.name() == b.name() && self.full_name() == b.full_name()
    }
}

/// `Variables`: a list of (borrowed) variables.
#[derive(Default)]
pub struct Variables<'v>(pub Vec<&'v dyn Variable>);

impl<'v> Variables<'v> {
    pub fn new() -> Self {
        Variables(Vec::new())
    }

    /// `contains(const Variable *)`
    pub fn contains_var(&self, v: &dyn Variable) -> bool {
        self.0.iter().any(|m| v.same_as(*m))
    }

    /// `contains(const VariableValue *)`
    pub fn contains_value(&self, v: &VariableValue) -> bool {
        self.0.iter().any(|m| match m.regex() {
            Some(r) => r.search(v.key()) > 0,
            None => v.key_with_collection() == m.full_name().as_bytes(),
        })
    }

    pub fn push(&mut self, v: &'v dyn Variable) {
        self.0.push(v);
    }
}

/// `operator+(std::string, const Variables *)`: full names joined by `|`.
pub fn variables_to_string<'a, I>(vars: I) -> String
where
    I: IntoIterator<Item = &'a dyn Variable>,
{
    let mut test = String::new();
    for b in vars {
        if test.is_empty() {
            test = b.full_name().to_string();
        } else {
            test = format!("{}|{}", test, b.full_name());
        }
    }
    test
}

// ---------------------------------------------------------------------------
// Generic variable kinds
// ---------------------------------------------------------------------------

/// `VariableDictElement`: `COLLECTION:element`.
#[derive(Debug)]
pub struct VariableDictElement {
    pub base: VariableBase,
    pub dict_element: String,
}

impl VariableDictElement {
    pub fn new(name: &str, dict_element: &str) -> Self {
        VariableDictElement {
            base: VariableBase::new(&format!("{}:{}", name, dict_element)),
            dict_element: dict_element.to_string(),
        }
    }
}

/// `VariableRegex`: `COLLECTION:/regex/`.
#[derive(Debug)]
pub struct VariableRegex {
    pub base: VariableBase,
    pub r: Regex,
    pub regex: String,
}

impl VariableRegex {
    pub fn new(name: &str, regex: &str) -> Self {
        VariableRegex {
            base: VariableBase::new(&format!("{}:regex({})", name, regex)),
            r: Regex::new_case(regex, true),
            regex: regex.to_string(),
        }
    }
}

/// `VariableModificatorExclusion`: `!VAR`.
#[derive(Debug)]
pub struct VariableModificatorExclusion {
    pub base: VariableBase,
    pub m_base: Box<dyn Variable>,
}

impl VariableModificatorExclusion {
    pub fn new(var: Box<dyn Variable>) -> Self {
        VariableModificatorExclusion { base: VariableBase::copy_of(var.base()), m_base: var }
    }
}

impl Variable for VariableModificatorExclusion {
    fn base(&self) -> &VariableBase {
        &self.base
    }
    fn base_mut(&mut self) -> &mut VariableBase {
        &mut self.base
    }
    fn evaluate(&self, t: &Transaction<'_>, rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        self.m_base.evaluate(t, rule, l);
    }
    fn exclusion_base(&self) -> Option<&dyn Variable> {
        Some(self.m_base.as_ref())
    }
}

/// `VariableModificatorCount`: `&VAR`.
#[derive(Debug)]
pub struct VariableModificatorCount {
    pub base: VariableBase,
    pub m_base: Box<dyn Variable>,
}

impl VariableModificatorCount {
    pub fn new(var: Box<dyn Variable>) -> Self {
        VariableModificatorCount { base: VariableBase::copy_of(var.base()), m_base: var }
    }
}

impl Variable for VariableModificatorCount {
    fn base(&self) -> &VariableBase {
        &self.base
    }
    fn base_mut(&mut self) -> &mut VariableBase {
        &mut self.base
    }
    fn evaluate(&self, t: &Transaction<'_>, rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        let mut resl_in = Vec::new();
        self.m_base.evaluate(t, rule, &mut resl_in);
        let count = resl_in.len();
        l.push(VariableValue::new(self.base.full_name.as_bytes(), count.to_string().as_bytes()));
    }
}

// ---------------------------------------------------------------------------
// The DEFINE_VARIABLE* macros
// ---------------------------------------------------------------------------

/// `VAR_DIRECT` / `DEFINE_VARIABLE(n, N, e)`: a single valued variable read
/// from the transaction's anchored variable `e`.
#[macro_export]
macro_rules! define_variable {
    ($n:ident, $N:literal, $e:ident) => {
        #[derive(Debug)]
        pub struct $n {
            pub base: $crate::variables::variable::VariableBase,
        }

        impl $n {
            pub fn new() -> Self {
                $n { base: $crate::variables::variable::VariableBase::new($N) }
            }
        }

        impl Default for $n {
            fn default() -> Self {
                Self::new()
            }
        }

        impl $crate::variables::variable::Variable for $n {
            fn base(&self) -> &$crate::variables::variable::VariableBase {
                &self.base
            }
            fn base_mut(&mut self) -> &mut $crate::variables::variable::VariableBase {
                &mut self.base
            }
            fn evaluate(
                &self,
                t: &$crate::transaction::Transaction<'_>,
                _rule: Option<&$crate::rule_with_actions::RuleWithActions>,
                l: &mut Vec<$crate::variable_value::VariableValue>,
            ) {
                t.vars.$e.evaluate_into(l);
            }
        }
    };
}

/// `DEFINE_VARIABLE_DICT(n, N, e)`: defines the C++ `n_DictElement`,
/// `n_NoDictElement` and `n_DictElementRegexp` classes over the transaction's
/// anchored set variable `e`. Rust macros cannot concatenate identifiers, so
/// the three types live in a module named after the variable:
/// `n::DictElement`, `n::NoDictElement` and `n::DictElementRegexp`.
#[macro_export]
macro_rules! define_variable_dict {
    ($n:ident, $N:literal, $e:ident) => {
        $crate::__define_dict_types!($n, $N, $e);
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! __define_dict_types {
    ($n:ident, $N:literal, $e:ident) => {
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
                    t.vars.$e.resolve_key(self.0.dict_element.as_bytes(), l);
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
                    t.vars.$e.resolve_with_exclusions(l, &self.0.key_exclusion, Some(t));
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

// ---------------------------------------------------------------------------
// VariableMonkeyResolution
// ---------------------------------------------------------------------------

/// Error raised by the by-name resolution helpers (`std::invalid_argument`
/// "Variable not found." in C++).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VariableNotFound;

impl std::fmt::Display for VariableNotFound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Variable not found.")
    }
}

impl std::error::Error for VariableNotFound {}

/// `VariableMonkeyResolution::comp`: `a` upper-cased equals `b`.
#[inline]
pub fn comp(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).all(|(x, y)| x.to_ascii_uppercase() == y)
}

/// `VariableMonkeyResolution::stringMatchResolveMulti`: resolves a variable
/// given by name (used by the Lua engine).
pub fn string_match_resolve_multi(
    t: &Transaction<'_>,
    variable: &str,
    l: &mut Vec<VariableValue>,
) -> Result<(), VariableNotFound> {
    let delim = variable.find('.').or_else(|| variable.find(':'));
    let (col, var) = match delim {
        None => (variable.to_string(), String::new()),
        Some(d) => (variable[..d].to_string(), variable[d + 1..].to_string()),
    };
    let v = &t.vars;
    let anchored = if comp(&col, "ARGS") {
        Some(&v.args)
    } else if comp(&col, "ARGS_GET") {
        Some(&v.args_get)
    } else if comp(&col, "ARGS_POST") {
        Some(&v.args_post)
    } else if comp(&col, "FILES_SIZES") {
        Some(&v.files_sizes)
    } else if comp(&col, "FILES_NAMES") {
        Some(&v.files_names)
    } else if comp(&col, "FILES_TMP_CONTENT") {
        Some(&v.files_tmp_content)
    } else if comp(&col, "MULTIPART_FILENAME") {
        Some(&v.multipart_file_name)
    } else if comp(&col, "MULTIPART_FILENAME_CHARSET") {
        Some(&v.multipart_file_name_charset)
    } else if comp(&col, "MULTIPART_FILENAME_LANGUAGE") {
        Some(&v.multipart_file_name_language)
    } else if comp(&col, "MULTIPART_NAME") {
        Some(&v.multipart_name)
    } else if comp(&col, "MATCHED_VARS_NAMES") {
        Some(&v.matched_vars_names)
    } else if comp(&col, "MATCHED_VARS") {
        Some(&v.matched_vars)
    } else if comp(&col, "FILES") {
        Some(&v.files)
    } else if comp(&col, "REQUEST_COOKIES") {
        Some(&v.request_cookies)
    } else if comp(&col, "REQUEST_HEADERS") {
        Some(&v.request_headers)
    } else if comp(variable, "REQUEST_HEADERS_NAMES") {
        Some(&v.request_headers_names)
    } else if comp(&col, "RESPONSE_HEADERS") {
        Some(&v.response_headers)
    } else if comp(variable, "RESPONSE_HEADERS_NAMES") {
        Some(&v.response_headers_names)
    } else if comp(&col, "GEO") {
        Some(&v.geo)
    } else if comp(&col, "REQUEST_COOKIES_NAMES") {
        Some(&v.request_cookies_names)
    } else if comp(&col, "MULTIPART_PART_HEADERS") {
        Some(&v.multipart_part_headers)
    } else if comp(&col, "FILES_TMPNAMES") {
        Some(&v.files_tmp_names)
    } else {
        None
    };
    if let Some(a) = anchored {
        if delim.is_none() {
            a.resolve(l);
        } else {
            a.resolve_key(var.as_bytes(), l);
        }
        return Ok(());
    }
    let proxy = if comp(&col, "ARGS_NAMES") {
        Some((&v.args_names, &v.args))
    } else if comp(&col, "ARGS_GET_NAMES") {
        Some((&v.args_get_names, &v.args_get))
    } else if comp(&col, "ARGS_POST_NAMES") {
        Some((&v.args_post_names, &v.args_post))
    } else {
        None
    };
    if let Some((p, fount)) = proxy {
        if delim.is_none() {
            p.resolve(fount, l);
        } else {
            p.resolve_key(fount, var.as_bytes(), l);
        }
        return Ok(());
    }
    if delim.is_some() {
        return Err(VariableNotFound);
    }
    match single_anchored(t, variable) {
        Some(a) => {
            a.evaluate_into(l);
            Ok(())
        }
        None => Err(VariableNotFound),
    }
}

/// The single valued anchored variables addressable by name, in the order
/// the C++ resolution tests them.
fn single_anchored<'t>(
    t: &'t Transaction<'_>,
    variable: &str,
) -> Option<&'t crate::anchored_variable::AnchoredVariable> {
    let v = &t.vars;
    let table: [(&str, &crate::anchored_variable::AnchoredVariable); 51] = [
        ("RESPONSE_CONTENT_TYPE", &v.response_content_type),
        ("ARGS_COMBINED_SIZE", &v.args_combined_size),
        ("AUTH_TYPE", &v.auth_type),
        ("FILES_COMBINED_SIZE", &v.files_combined_size),
        ("FULL_REQUEST", &v.full_request),
        ("FULL_REQUEST_LENGTH", &v.full_request_length),
        ("INBOUND_DATA_ERROR", &v.inbound_data_error),
        ("MATCHED_VAR", &v.matched_var),
        ("MATCHED_VAR_NAME", &v.matched_var_name),
        ("MSC_PCRE_ERROR", &v.msc_pcre_error),
        ("MSC_PCRE_LIMITS_EXCEEDED", &v.msc_pcre_limits_exceeded),
        ("MULTIPART_CRLF_LF_LINES", &v.multipart_crlf_lf_lines),
        ("MULTIPART_DATA_AFTER", &v.multipart_data_after),
        ("MULTIPART_DUPLICATE_PART_HEADER", &v.multipart_duplicate_part_header),
        ("MULTIPART_FILE_LIMIT_EXCEEDED", &v.multipart_file_limit_exceeded),
        ("MULTIPART_STRICT_ERROR", &v.multipart_strict_error),
        ("MULTIPART_HEADER_FOLDING", &v.multipart_header_folding),
        ("MULTIPART_INVALID_QUOTING", &v.multipart_invalid_quoting),
        ("MULTIPART_INVALID_HEADER_FOLDING", &v.multipart_invalid_header_folding),
        ("MULTIPART_UNMATCHED_BOUNDARY", &v.multipart_unmatched_boundary),
        ("OUTBOUND_DATA_ERROR", &v.outbound_data_error),
        ("PATH_INFO", &v.path_info),
        ("QUERY_STRING", &v.query_string),
        ("REMOTE_ADDR", &v.remote_addr),
        ("REMOTE_HOST", &v.remote_host),
        ("REMOTE_PORT", &v.remote_port),
        ("REQBODY_ERROR", &v.reqbody_error),
        ("REQBODY_ERROR_MSG", &v.reqbody_error_msg),
        ("REQBODY_PROCESSOR_ERROR_MSG", &v.reqbody_processor_error_msg),
        ("REQBODY_PROCESSOR_ERROR", &v.reqbody_processor_error),
        ("REQBODY_PROCESSOR", &v.reqbody_processor),
        ("REQUEST_BASENAME", &v.request_basename),
        ("REQUEST_BODY", &v.request_body),
        ("REQUEST_BODY_LENGTH", &v.request_body_length),
        ("REQUEST_FILENAME", &v.request_filename),
        ("REQUEST_LINE", &v.request_line),
        ("REQUEST_METHOD", &v.request_method),
        ("REQUEST_PROTOCOL", &v.request_protocol),
        ("REQUEST_URI", &v.request_uri),
        ("REQUEST_URI_RAW", &v.request_uri_raw),
        ("RESOURCE", &v.resource),
        ("RESPONSE_BODY", &v.response_body),
        ("RESPONSE_CONTENT_LENGTH", &v.response_content_length),
        ("RESPONSE_PROTOCOL", &v.response_protocol),
        ("RESPONSE_STATUS", &v.response_status),
        ("SERVER_ADDR", &v.server_addr),
        ("SERVER_NAME", &v.server_name),
        ("SERVER_PORT", &v.server_port),
        ("SESSIONID", &v.session_id),
        ("UNIQUE_ID", &v.unique_id),
        ("URLENCODED_ERROR", &v.url_encoded_error),
    ];
    if comp(variable, "USERID") {
        return Some(&v.user_id);
    }
    table.iter().find(|(n, _)| comp(variable, n)).map(|(_, a)| *a)
}

/// `VariableMonkeyResolution::stringMatchResolve`: resolves a variable given
/// by name to its first value (empty if none).
pub fn string_match_resolve(t: &Transaction<'_>, variable: &str) -> Result<Vec<u8>, VariableNotFound> {
    let collection = variable.find('.').or_else(|| variable.find(':'));
    use crate::collection::collection::Collection;
    let web_app_id = t.rules.properties.web_app_id();
    let cols = &t.collections;
    let vv: Option<Vec<u8>> = match collection {
        None => {
            if let Some(a) = single_anchored(t, variable) {
                // RESOURCE is matched as an anchored variable first, as in
                // the C++ if/else chain.
                a.resolve_first()
            } else if comp(variable, "TX") {
                cols.tx_collection.resolve_first(b"")
            } else if comp(variable, "USER") {
                cols.user_collection.resolve_first_c(b"", &cols.user_collection_key, Some(web_app_id))
            } else if comp(variable, "SESSION") {
                cols.session_collection.resolve_first_c(b"", &cols.session_collection_key, Some(web_app_id))
            } else if comp(variable, "IP") {
                cols.ip_collection.resolve_first_c(b"", &cols.ip_collection_key, Some(web_app_id))
            } else if comp(variable, "GLOBAL") {
                cols.global_collection.resolve_first_c(b"", &cols.global_collection_key, Some(web_app_id))
            } else {
                return Err(VariableNotFound);
            }
        }
        Some(c) => {
            let col = &variable[..c];
            let var = &variable.as_bytes()[c + 1..];
            let v = &t.vars;
            if comp(col, "ARGS") {
                v.args.resolve_first(var)
            } else if comp(variable, "ARGS_NAMES") {
                v.args_names.resolve_first(&v.args, var)
            } else if comp(col, "ARGS_GET") {
                v.args_get.resolve_first(var)
            } else if comp(variable, "ARGS_GET_NAMES") {
                v.args_get_names.resolve_first(&v.args_get, var)
            } else if comp(col, "ARGS_POST") {
                v.args_post.resolve_first(var)
            } else if comp(variable, "ARGS_POST_NAMES") {
                v.args_post_names.resolve_first(&v.args_post, var)
            } else if comp(col, "FILES_SIZES") {
                v.files_sizes.resolve_first(var)
            } else if comp(col, "FILES_NAMES") {
                v.files_names.resolve_first(var)
            } else if comp(col, "FILES_TMP_CONTENT") {
                v.files_tmp_content.resolve_first(var)
            } else if comp(col, "MULTIPART_FILENAME") {
                v.multipart_file_name.resolve_first(var)
            } else if comp(col, "MULTIPART_FILENAME_CHARSET") {
                v.multipart_file_name_charset.resolve_first(var)
            } else if comp(col, "MULTIPART_FILENAME_LANGUAGE") {
                v.multipart_file_name_language.resolve_first(var)
            } else if comp(col, "MULTIPART_NAME") {
                v.multipart_name.resolve_first(var)
            } else if comp(col, "MATCHED_VARS_NAMES") {
                v.matched_vars_names.resolve_first(var)
            } else if comp(col, "MATCHED_VARS") {
                v.matched_vars.resolve_first(var)
            } else if comp(col, "FILES") {
                v.files.resolve_first(var)
            } else if comp(col, "REQUEST_COOKIES") {
                v.request_cookies.resolve_first(var)
            } else if comp(col, "REQUEST_HEADERS") {
                v.request_headers.resolve_first(var)
            } else if comp(variable, "REQUEST_HEADERS_NAMES") {
                v.request_headers_names.resolve_first(var)
            } else if comp(col, "RESPONSE_HEADERS") {
                v.response_headers.resolve_first(var)
            } else if comp(variable, "RESPONSE_HEADERS_NAMES") {
                v.response_headers_names.resolve_first(var)
            } else if comp(col, "GEO") {
                v.geo.resolve_first(var)
            } else if comp(col, "REQUEST_COOKIES_NAMES") {
                v.request_cookies_names.resolve_first(var)
            } else if comp(col, "MULTIPART_PART_HEADERS") {
                v.multipart_part_headers.resolve_first(var)
            } else if comp(col, "FILES_TMPNAMES") {
                v.files_tmp_names.resolve_first(var)
            } else if comp(col, "TX") {
                cols.tx_collection.resolve_first(var)
            } else if comp(col, "RESOURCE") {
                cols.resource_collection.resolve_first_c(var, &cols.resource_collection_key, Some(web_app_id))
            } else if comp(col, "USER") {
                cols.user_collection.resolve_first_c(var, &cols.user_collection_key, Some(web_app_id))
            } else if comp(col, "SESSION") {
                cols.session_collection.resolve_first_c(var, &cols.session_collection_key, Some(web_app_id))
            } else if comp(col, "IP") {
                cols.ip_collection.resolve_first_c(var, &cols.ip_collection_key, Some(web_app_id))
            } else if comp(col, "GLOBAL") {
                cols.global_collection.resolve_first_c(var, &cols.global_collection_key, Some(web_app_id))
            } else {
                return Err(VariableNotFound);
            }
        }
    };
    Ok(vv.unwrap_or_default())
}
