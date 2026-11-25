//! The variables a transaction holds, declared once: the table below
//! makes the [`TransactionVariables`] struct (one field per variable), its
//! constructor, and the rows that SecLang targets
//! ([`new_variable`](super::new_variable)) and the Lua engine's lookup by
//! name (`m.getvar`, `variable::string_match_resolve*`) read.
//!
//! The two lookups reach different subsets: Lua does not know six of the
//! `MULTIPART_*` flags nor the SecLang aliases (`STATUS`, ...), and its
//! `RESOURCE` is the single variable set by `setrsc` where SecLang's is
//! the persistent collection. The variables with logic of their own (the
//! collections, `RULE`, `ENV`, `XML`, the computed ones) are not in the
//! table.

use crate::variables::multi::MultiVariable;
use crate::variables::single::SingleVariable;

type Vars = TransactionVariables;

/// How a single valued variable is found by name.
pub(crate) struct Single {
    /// The name in rules and Lua (upper case). It is also the key of the
    /// variable's value.
    pub(crate) token: &'static str,
    /// The name of the SecLang variable, as it shows in the logs. For a
    /// few it differs from the token (sic: `UNIQUEID`, `PROCESSOR_ERROR_MSG`).
    pub(crate) name: &'static str,
    pub(crate) get: fn(&Vars) -> &SingleVariable,
    /// Whether SecLang targets know it.
    pub(crate) seclang: bool,
    /// Whether Lua's lookup by name knows it.
    #[cfg_attr(not(feature = "lua"), allow(dead_code))]
    pub(crate) lua: bool,
}

impl Single {
    /// Known to both lookups, named after its token.
    const fn new(token: &'static str, get: fn(&Vars) -> &SingleVariable) -> Self {
        Single { token, name: token, get, seclang: true, lua: true }
    }

    /// Another SecLang name of a variable.
    const fn alias(token: &'static str, get: fn(&Vars) -> &SingleVariable) -> Self {
        Single { lua: false, ..Single::new(token, get) }
    }
}

/// How a multi valued variable is found by name.
pub(crate) struct Multi {
    /// The name in rules and Lua, and the collection of its values.
    pub(crate) token: &'static str,
    pub(crate) get: fn(&Vars) -> &MultiVariable,
    /// The name of the variable of its keys (`ARGS_NAMES`), if it has one
    /// (see [`MultiVariable::names`]).
    pub(crate) names: Option<&'static str>,
    /// Lua's lookup compares the whole name, key included, with the token
    /// (sic), so it finds the variable only without a key.
    #[cfg_attr(not(feature = "lua"), allow(dead_code))]
    pub(crate) lua_whole_name: bool,
}

impl Multi {
    const fn new(token: &'static str, get: fn(&Vars) -> &MultiVariable) -> Self {
        Multi { token, get, names: None, lua_whole_name: false }
    }

    fn variable(&self) -> MultiVariable {
        match self.names {
            Some(names) => MultiVariable::with_names(self.token, names),
            None => MultiVariable::new(self.token),
        }
    }
}

/// Declares the variables: `field: "TOKEN"`, optionally followed by
/// `{ ... }` with the fields of its [`Single`] or [`Multi`] row that differ
/// from the defaults; `aliases` are more rows for a declared single
/// variable.
macro_rules! transaction_variables {
    (
        single { $( $sf:ident : $st:literal $({ $($sk:ident : $sv:expr),* $(,)? })? ),* $(,)? }
        multi { $( $mf:ident : $mt:literal $({ $($mk:ident : $mv:expr),* $(,)? })? ),* $(,)? }
        aliases { $( $at:literal => $af:ident $({ $($ak:ident : $av:expr),* $(,)? })? ),* $(,)? }
    ) => {
        /// The variables of a transaction that hold what it was given and
        /// what it computed (`REQUEST_METHOD`, `ARGS`, ...), one field
        /// each. Each is empty, and allocates nothing, until it is set.
        #[derive(Debug, Clone)]
        pub struct TransactionVariables {
            $( pub $sf: SingleVariable, )*
            $( pub $mf: MultiVariable, )*
            /// Where in the request the value being set starts.
            pub offset: usize,
        }

        impl TransactionVariables {
            pub fn new() -> Self {
                TransactionVariables {
                    $( $sf: SingleVariable::new($st), )*
                    $( $mf: {
                        const ROW: Multi = Multi { $($($mk: $mv,)*)? ..Multi::new($mt, |v| &v.$mf) };
                        ROW.variable()
                    }, )*
                    offset: 0,
                }
            }
        }

        /// The single valued variables, then the aliases.
        pub(crate) static SINGLE: &[Single] = &[
            $( Single { $($($sk: $sv,)*)? ..Single::new($st, |v| &v.$sf) }, )*
            $( Single { $($($ak: $av,)*)? ..Single::alias($at, |v| &v.$af) }, )*
        ];

        /// The multi valued variables.
        pub(crate) static MULTI: &[Multi] = &[
            $( Multi { $($($mk: $mv,)*)? ..Multi::new($mt, |v| &v.$mf) }, )*
        ];
    };
}

transaction_variables! {
    single {
        args_combined_size: "ARGS_COMBINED_SIZE",
        auth_type: "AUTH_TYPE",
        files_combined_size: "FILES_COMBINED_SIZE",
        full_request: "FULL_REQUEST",
        full_request_length: "FULL_REQUEST_LENGTH",
        inbound_data_error: "INBOUND_DATA_ERROR",
        matched_var: "MATCHED_VAR",
        matched_var_name: "MATCHED_VAR_NAME",
        msc_pcre_error: "MSC_PCRE_ERROR",
        msc_pcre_limits_exceeded: "MSC_PCRE_LIMITS_EXCEEDED",
        multipart_boundary_quoted: "MULTIPART_BOUNDARY_QUOTED" { lua: false },
        multipart_boundary_white_space: "MULTIPART_BOUNDARY_WHITESPACE" { lua: false },
        multipart_crlf_lf_lines: "MULTIPART_CRLF_LF_LINES",
        multipart_data_after: "MULTIPART_DATA_AFTER",
        multipart_data_before: "MULTIPART_DATA_BEFORE" { lua: false },
        multipart_duplicate_part_header: "MULTIPART_DUPLICATE_PART_HEADER",
        multipart_file_limit_exceeded: "MULTIPART_FILE_LIMIT_EXCEEDED",
        multipart_header_folding: "MULTIPART_HEADER_FOLDING",
        multipart_invalid_header_folding: "MULTIPART_INVALID_HEADER_FOLDING",
        multipart_invalid_part: "MULTIPART_INVALID_PART" { lua: false },
        multipart_invalid_quoting: "MULTIPART_INVALID_QUOTING",
        multipart_lf_line: "MULTIPART_LF_LINE" { lua: false },
        multipart_missing_semicolon: "MULTIPART_MISSING_SEMICOLON" { lua: false },
        multipart_strict_error: "MULTIPART_STRICT_ERROR",
        multipart_unmatched_boundary: "MULTIPART_UNMATCHED_BOUNDARY",
        outbound_data_error: "OUTBOUND_DATA_ERROR",
        path_info: "PATH_INFO",
        query_string: "QUERY_STRING",
        remote_addr: "REMOTE_ADDR",
        remote_host: "REMOTE_HOST",
        remote_port: "REMOTE_PORT",
        reqbody_error: "REQBODY_ERROR",
        reqbody_error_msg: "REQBODY_ERROR_MSG",
        reqbody_processor: "REQBODY_PROCESSOR",
        reqbody_processor_error: "REQBODY_PROCESSOR_ERROR",
        reqbody_processor_error_msg: "REQBODY_PROCESSOR_ERROR_MSG" { name: "PROCESSOR_ERROR_MSG" },
        request_basename: "REQUEST_BASENAME",
        request_body: "REQUEST_BODY",
        request_body_length: "REQUEST_BODY_LENGTH",
        request_filename: "REQUEST_FILENAME",
        request_line: "REQUEST_LINE",
        request_method: "REQUEST_METHOD",
        request_protocol: "REQUEST_PROTOCOL",
        request_uri: "REQUEST_URI",
        request_uri_raw: "REQUEST_URI_RAW",
        // `setrsc`'s value. In SecLang, `RESOURCE` is the persistent
        // collection.
        resource: "RESOURCE" { seclang: false },
        response_body: "RESPONSE_BODY",
        response_content_length: "RESPONSE_CONTENT_LENGTH",
        response_content_type: "RESPONSE_CONTENT_TYPE",
        response_protocol: "RESPONSE_PROTOCOL",
        response_status: "RESPONSE_STATUS",
        server_addr: "SERVER_ADDR",
        server_name: "SERVER_NAME",
        server_port: "SERVER_PORT",
        session_id: "SESSIONID",
        unique_id: "UNIQUE_ID" { name: "UNIQUEID" },
        url_encoded_error: "URLENCODED_ERROR",
        user_id: "USERID",
    }
    multi {
        args: "ARGS" { names: Some("ARGS_NAMES") },
        args_get: "ARGS_GET" { names: Some("ARGS_GET_NAMES") },
        args_post: "ARGS_POST" { names: Some("ARGS_POST_NAMES") },
        files: "FILES",
        files_names: "FILES_NAMES",
        files_sizes: "FILES_SIZES",
        files_tmp_content: "FILES_TMP_CONTENT",
        files_tmp_names: "FILES_TMPNAMES",
        geo: "GEO",
        matched_vars: "MATCHED_VARS",
        matched_vars_names: "MATCHED_VARS_NAMES",
        multipart_file_name: "MULTIPART_FILENAME",
        multipart_file_name_charset: "MULTIPART_FILENAME_CHARSET",
        multipart_file_name_language: "MULTIPART_FILENAME_LANGUAGE",
        multipart_name: "MULTIPART_NAME",
        multipart_part_headers: "MULTIPART_PART_HEADERS",
        request_cookies: "REQUEST_COOKIES",
        request_cookies_names: "REQUEST_COOKIES_NAMES",
        request_headers: "REQUEST_HEADERS",
        request_headers_names: "REQUEST_HEADERS_NAMES" { lua_whole_name: true },
        response_headers: "RESPONSE_HEADERS",
        response_headers_names: "RESPONSE_HEADERS_NAMES" { lua_whole_name: true },
    }
    aliases {
        "MULTIPART_SEMICOLON_MISSING" => multipart_missing_semicolon { name: "MULTIPART_MISSING_SEMICOLON" },
        "STATUS" => response_status,
        "STATUS_LINE" => response_status { name: "STATUS" },
    }
}

impl Default for TransactionVariables {
    fn default() -> Self {
        Self::new()
    }
}

impl TransactionVariables {
    /// Records a matched target, its name `key` and its (transformed)
    /// `value`, in `MATCHED_VAR`, `MATCHED_VAR_NAME`, `MATCHED_VARS` and
    /// `MATCHED_VARS_NAMES`.
    pub(crate) fn record_match(&mut self, key: &[u8], value: &[u8]) {
        let off = self.offset;
        self.matched_var.set(value, off);
        self.matched_var_name.set(key, off);
        self.matched_vars.set(key, value, off);
        self.matched_vars_names.set(key, key, off);
    }

    /// Empties the four variables of [`Self::record_match`] (after each
    /// rule).
    pub(crate) fn clear_matches(&mut self) {
        // Every match adds to MATCHED_VARS, so when that is empty nothing
        // matched since the last clearing and there is nothing to unset.
        if self.matched_vars.is_empty() {
            return;
        }
        self.matched_var.unset();
        self.matched_vars.unset();
        self.matched_var_name.unset();
        self.matched_vars_names.unset();
    }
}

/// The multi valued variable whose names variable (`ARGS_NAMES`, ...) is
/// the one `matches` accepts.
pub(crate) fn names_of(matches: impl Fn(&str) -> bool) -> Option<&'static Multi> {
    MULTI.iter().find(|m| m.names.is_some_and(&matches))
}

/// No name is declared twice.
#[cfg(test)]
#[test]
fn names_are_unique() {
    let mut names: Vec<&str> = SINGLE.iter().map(|v| v.token).collect();
    names.extend(MULTI.iter().map(|v| v.token));
    names.extend(MULTI.iter().filter_map(|v| v.names));
    let count = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), count);
}

/// Where the two lookups differ. (When this table replaced the three
/// hand-written lookups, the old and the new ones were compared on every
/// name, spelling and selector.)
#[cfg(all(test, feature = "lua"))]
mod tests {
    use crate::instance::ModSecurity;
    use crate::rules_set::RulesSet;
    use crate::transaction::Transaction;
    use crate::variables::variable::{string_match_resolve, string_match_resolve_multi};
    use crate::variables::{VariableSelector, new_variable};

    #[test]
    fn seclang_and_lua_lookups_differ_as_in_cxx() {
        let ms = ModSecurity::new();
        let rules = RulesSet::new();
        let mut t = Transaction::new(&ms, &rules, None);
        t.vars.resource.set(b"setrsc-value", 0);
        t.vars.multipart_lf_line.set(b"1", 0);
        t.vars.unique_id.set(b"uid", 0);
        t.vars.args.set(b"k", b"v", 0);
        t.vars.request_headers_names.set(b"k", b"Host", 0);

        let seclang = |n: &str| new_variable(n, VariableSelector::None).ok().map(|v| v.full_name().to_string());
        // RESOURCE: the persistent collection in SecLang, `setrsc`'s value
        // in Lua.
        assert_eq!(seclang("RESOURCE").as_deref(), Some("RESOURCE"));
        assert_eq!(string_match_resolve(&t, "RESOURCE").unwrap(), b"setrsc-value");
        // Six MULTIPART_* flags and STATUS are SecLang only.
        assert_eq!(seclang("multipart_lf_line").as_deref(), Some("MULTIPART_LF_LINE"));
        assert!(string_match_resolve(&t, "MULTIPART_LF_LINE").is_err());
        assert_eq!(seclang("STATUS_LINE").as_deref(), Some("STATUS"));
        assert!(string_match_resolve(&t, "STATUS").is_err());
        // Names that differ from the token (sic).
        assert_eq!(seclang("UNIQUE_ID").as_deref(), Some("UNIQUEID"));
        assert_eq!(seclang("REQBODY_PROCESSOR_ERROR_MSG").as_deref(), Some("PROCESSOR_ERROR_MSG"));
        assert_eq!(string_match_resolve(&t, "unique_id").unwrap(), b"uid");
        // Lua compares REQUEST_HEADERS_NAMES with the whole name, key
        // included: found without a key only.
        let mut l = Vec::new();
        assert!(string_match_resolve_multi(&t, "REQUEST_HEADERS_NAMES", &mut l).is_ok());
        assert_eq!(l.len(), 1);
        assert!(string_match_resolve_multi(&t, "REQUEST_HEADERS_NAMES:k", &mut Vec::new()).is_err());
        // ARGS_NAMES: found with a key by the multi-value lookup, never by
        // the single-value one.
        let mut l = Vec::new();
        assert!(string_match_resolve_multi(&t, "ARGS_NAMES:k", &mut l).is_ok());
        assert_eq!(l[0].value(), b"k");
        assert!(string_match_resolve(&t, "ARGS_NAMES:k").is_err());
        assert!(string_match_resolve(&t, "ARGS_NAMES").is_err());
    }
}
