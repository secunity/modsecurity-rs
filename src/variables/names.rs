//! The variables of the transaction by name: the one table that both
//! SecLang targets ([`new_variable`](super::new_variable)) and the Lua
//! engine's lookup by name (`m.getvar`, `variable::string_match_resolve*`)
//! read.
//!
//! The two lookups reach different subsets, as their C++ counterparts do
//! (the grammar's tokens and `Variable::stringMatchResolve`): Lua does not
//! know six of the `MULTIPART_*` flags nor `STATUS`, and its `RESOURCE` is
//! the single variable set by `setrsc` where SecLang's is the persistent
//! collection. The variables with logic of their own (the collections,
//! `RULE`, `ENV`, `XML`, the computed ones) are not in these tables.

use crate::transaction::TransactionAnchoredVariables as Vars;
use crate::variables::anchored_set_variable::AnchoredSetVariable;
use crate::variables::anchored_set_variable_translation_proxy::AnchoredSetVariableTranslationProxy;
use crate::variables::anchored_variable::AnchoredVariable;

/// A single valued variable of the transaction.
pub(crate) struct Single {
    /// The name in rules and Lua (upper case).
    pub(crate) token: &'static str,
    /// The name of the SecLang variable: the C++ class name, which for a
    /// few differs from the token (sic: `UNIQUEID`, `PROCESSOR_ERROR_MSG`).
    pub(crate) name: &'static str,
    pub(crate) get: fn(&Vars) -> &AnchoredVariable,
    /// Whether SecLang targets know it.
    pub(crate) seclang: bool,
    /// Whether Lua's lookup by name knows it.
    #[cfg_attr(not(feature = "lua"), allow(dead_code))]
    pub(crate) lua: bool,
}

/// A multi valued variable of the transaction.
pub(crate) struct Set {
    pub(crate) token: &'static str,
    pub(crate) get: fn(&Vars) -> &AnchoredSetVariable,
    /// Lua's lookup compares the whole name, key included, with the token
    /// (sic, as in C++), so it finds the variable only without a key.
    #[cfg_attr(not(feature = "lua"), allow(dead_code))]
    pub(crate) lua_whole_name: bool,
}

/// The names of a multi valued variable (`ARGS_NAMES`): the proxy and the
/// variable it translates.
pub(crate) struct Names {
    pub(crate) token: &'static str,
    pub(crate) get: fn(&Vars) -> (&AnchoredSetVariableTranslationProxy, &AnchoredSetVariable),
}

macro_rules! single {
    ($t:literal, $n:literal, $f:ident, seclang: $s:literal, lua: $l:literal) => {
        Single {
            token: $t,
            name: $n,
            get: {
                fn get(v: &Vars) -> &AnchoredVariable {
                    &v.$f
                }
                get
            },
            seclang: $s,
            lua: $l,
        }
    };
}

macro_rules! set {
    ($t:literal, $f:ident, lua_whole_name: $w:literal) => {
        Set {
            token: $t,
            get: {
                fn get(v: &Vars) -> &AnchoredSetVariable {
                    &v.$f
                }
                get
            },
            lua_whole_name: $w,
        }
    };
}

macro_rules! names {
    ($t:literal, $proxy:ident, $fount:ident) => {
        Names {
            token: $t,
            get: {
                fn get(v: &Vars) -> (&AnchoredSetVariableTranslationProxy, &AnchoredSetVariable) {
                    (&v.$proxy, &v.$fount)
                }
                get
            },
        }
    };
}

/// The single valued variables (C++ `DEFINE_VARIABLE`).
pub(crate) static SINGLE: &[Single] = &[
    single!("RESPONSE_CONTENT_TYPE", "RESPONSE_CONTENT_TYPE", response_content_type, seclang: true, lua: true),
    single!("ARGS_COMBINED_SIZE", "ARGS_COMBINED_SIZE", args_combined_size, seclang: true, lua: true),
    single!("AUTH_TYPE", "AUTH_TYPE", auth_type, seclang: true, lua: true),
    single!("FILES_COMBINED_SIZE", "FILES_COMBINED_SIZE", files_combined_size, seclang: true, lua: true),
    single!("FULL_REQUEST", "FULL_REQUEST", full_request, seclang: true, lua: true),
    single!("FULL_REQUEST_LENGTH", "FULL_REQUEST_LENGTH", full_request_length, seclang: true, lua: true),
    single!("INBOUND_DATA_ERROR", "INBOUND_DATA_ERROR", inbound_data_error, seclang: true, lua: true),
    single!("MATCHED_VAR", "MATCHED_VAR", matched_var, seclang: true, lua: true),
    single!("MATCHED_VAR_NAME", "MATCHED_VAR_NAME", matched_var_name, seclang: true, lua: true),
    single!("MSC_PCRE_ERROR", "MSC_PCRE_ERROR", msc_pcre_error, seclang: true, lua: true),
    single!("MSC_PCRE_LIMITS_EXCEEDED", "MSC_PCRE_LIMITS_EXCEEDED", msc_pcre_limits_exceeded, seclang: true, lua: true),
    single!("MULTIPART_BOUNDARY_QUOTED", "MULTIPART_BOUNDARY_QUOTED", multipart_boundary_quoted, seclang: true, lua: false),
    single!("MULTIPART_BOUNDARY_WHITESPACE", "MULTIPART_BOUNDARY_WHITESPACE", multipart_boundary_white_space, seclang: true, lua: false),
    single!("MULTIPART_CRLF_LF_LINES", "MULTIPART_CRLF_LF_LINES", multipart_crlf_lf_lines, seclang: true, lua: true),
    single!("MULTIPART_DATA_AFTER", "MULTIPART_DATA_AFTER", multipart_data_after, seclang: true, lua: true),
    single!("MULTIPART_DATA_BEFORE", "MULTIPART_DATA_BEFORE", multipart_data_before, seclang: true, lua: false),
    single!("MULTIPART_DUPLICATE_PART_HEADER", "MULTIPART_DUPLICATE_PART_HEADER", multipart_duplicate_part_header, seclang: true, lua: true),
    single!("MULTIPART_FILE_LIMIT_EXCEEDED", "MULTIPART_FILE_LIMIT_EXCEEDED", multipart_file_limit_exceeded, seclang: true, lua: true),
    single!("MULTIPART_HEADER_FOLDING", "MULTIPART_HEADER_FOLDING", multipart_header_folding, seclang: true, lua: true),
    single!("MULTIPART_INVALID_HEADER_FOLDING", "MULTIPART_INVALID_HEADER_FOLDING", multipart_invalid_header_folding, seclang: true, lua: true),
    single!("MULTIPART_INVALID_PART", "MULTIPART_INVALID_PART", multipart_invalid_part, seclang: true, lua: false),
    single!("MULTIPART_INVALID_QUOTING", "MULTIPART_INVALID_QUOTING", multipart_invalid_quoting, seclang: true, lua: true),
    single!("MULTIPART_LF_LINE", "MULTIPART_LF_LINE", multipart_lf_line, seclang: true, lua: false),
    single!("MULTIPART_MISSING_SEMICOLON", "MULTIPART_MISSING_SEMICOLON", multipart_missing_semicolon, seclang: true, lua: false),
    single!("MULTIPART_SEMICOLON_MISSING", "MULTIPART_MISSING_SEMICOLON", multipart_missing_semicolon, seclang: true, lua: false),
    single!("MULTIPART_STRICT_ERROR", "MULTIPART_STRICT_ERROR", multipart_strict_error, seclang: true, lua: true),
    single!("MULTIPART_UNMATCHED_BOUNDARY", "MULTIPART_UNMATCHED_BOUNDARY", multipart_unmatched_boundary, seclang: true, lua: true),
    single!("OUTBOUND_DATA_ERROR", "OUTBOUND_DATA_ERROR", outbound_data_error, seclang: true, lua: true),
    single!("PATH_INFO", "PATH_INFO", path_info, seclang: true, lua: true),
    single!("QUERY_STRING", "QUERY_STRING", query_string, seclang: true, lua: true),
    single!("REMOTE_ADDR", "REMOTE_ADDR", remote_addr, seclang: true, lua: true),
    single!("REMOTE_HOST", "REMOTE_HOST", remote_host, seclang: true, lua: true),
    single!("REMOTE_PORT", "REMOTE_PORT", remote_port, seclang: true, lua: true),
    single!("REQBODY_ERROR", "REQBODY_ERROR", reqbody_error, seclang: true, lua: true),
    single!("REQBODY_ERROR_MSG", "REQBODY_ERROR_MSG", reqbody_error_msg, seclang: true, lua: true),
    single!("REQBODY_PROCESSOR", "REQBODY_PROCESSOR", reqbody_processor, seclang: true, lua: true),
    single!("REQBODY_PROCESSOR_ERROR", "REQBODY_PROCESSOR_ERROR", reqbody_processor_error, seclang: true, lua: true),
    single!("REQBODY_PROCESSOR_ERROR_MSG", "PROCESSOR_ERROR_MSG", reqbody_processor_error_msg, seclang: true, lua: true),
    single!("REQUEST_BASENAME", "REQUEST_BASENAME", request_basename, seclang: true, lua: true),
    single!("REQUEST_BODY", "REQUEST_BODY", request_body, seclang: true, lua: true),
    single!("REQUEST_BODY_LENGTH", "REQUEST_BODY_LENGTH", request_body_length, seclang: true, lua: true),
    single!("REQUEST_FILENAME", "REQUEST_FILENAME", request_filename, seclang: true, lua: true),
    single!("REQUEST_LINE", "REQUEST_LINE", request_line, seclang: true, lua: true),
    single!("REQUEST_METHOD", "REQUEST_METHOD", request_method, seclang: true, lua: true),
    single!("REQUEST_PROTOCOL", "REQUEST_PROTOCOL", request_protocol, seclang: true, lua: true),
    single!("REQUEST_URI", "REQUEST_URI", request_uri, seclang: true, lua: true),
    single!("REQUEST_URI_RAW", "REQUEST_URI_RAW", request_uri_raw, seclang: true, lua: true),
    single!("RESPONSE_BODY", "RESPONSE_BODY", response_body, seclang: true, lua: true),
    single!("RESPONSE_CONTENT_LENGTH", "RESPONSE_CONTENT_LENGTH", response_content_length, seclang: true, lua: true),
    single!("RESPONSE_PROTOCOL", "RESPONSE_PROTOCOL", response_protocol, seclang: true, lua: true),
    single!("RESPONSE_STATUS", "RESPONSE_STATUS", response_status, seclang: true, lua: true),
    single!("SERVER_ADDR", "SERVER_ADDR", server_addr, seclang: true, lua: true),
    single!("SERVER_NAME", "SERVER_NAME", server_name, seclang: true, lua: true),
    single!("SERVER_PORT", "SERVER_PORT", server_port, seclang: true, lua: true),
    single!("SESSIONID", "SESSIONID", session_id, seclang: true, lua: true),
    single!("UNIQUE_ID", "UNIQUEID", unique_id, seclang: true, lua: true),
    single!("URLENCODED_ERROR", "URLENCODED_ERROR", url_encoded_error, seclang: true, lua: true),
    single!("USERID", "USERID", user_id, seclang: true, lua: true),
    single!("STATUS", "STATUS", response_status, seclang: true, lua: false),
    single!("STATUS_LINE", "STATUS", response_status, seclang: true, lua: false),
    single!("RESOURCE", "RESOURCE", resource, seclang: false, lua: true),
];

/// The multi valued variables (C++ `DEFINE_VARIABLE_DICT`).
pub(crate) static SETS: &[Set] = &[
    set!("ARGS", args, lua_whole_name: false),
    set!("ARGS_POST", args_post, lua_whole_name: false),
    set!("ARGS_GET", args_get, lua_whole_name: false),
    set!("FILES_SIZES", files_sizes, lua_whole_name: false),
    set!("FILES_NAMES", files_names, lua_whole_name: false),
    set!("FILES_TMP_CONTENT", files_tmp_content, lua_whole_name: false),
    set!("MULTIPART_FILENAME", multipart_file_name, lua_whole_name: false),
    set!("MULTIPART_FILENAME_CHARSET", multipart_file_name_charset, lua_whole_name: false),
    set!("MULTIPART_FILENAME_LANGUAGE", multipart_file_name_language, lua_whole_name: false),
    set!("MULTIPART_NAME", multipart_name, lua_whole_name: false),
    set!("MATCHED_VARS_NAMES", matched_vars_names, lua_whole_name: false),
    set!("MATCHED_VARS", matched_vars, lua_whole_name: false),
    set!("FILES", files, lua_whole_name: false),
    set!("REQUEST_COOKIES", request_cookies, lua_whole_name: false),
    set!("REQUEST_HEADERS", request_headers, lua_whole_name: false),
    set!("RESPONSE_HEADERS", response_headers, lua_whole_name: false),
    set!("GEO", geo, lua_whole_name: false),
    set!("REQUEST_COOKIES_NAMES", request_cookies_names, lua_whole_name: false),
    set!("MULTIPART_PART_HEADERS", multipart_part_headers, lua_whole_name: false),
    set!("FILES_TMPNAMES", files_tmp_names, lua_whole_name: false),
    set!("REQUEST_HEADERS_NAMES", request_headers_names, lua_whole_name: true),
    set!("RESPONSE_HEADERS_NAMES", response_headers_names, lua_whole_name: true),
];

/// The names of the multi valued variables, through their proxies.
pub(crate) static NAMES: &[Names] = &[
    names!("ARGS_NAMES", args_names, args),
    names!("ARGS_GET_NAMES", args_get_names, args_get),
    names!("ARGS_POST_NAMES", args_post_names, args_post),
];

/// Where the two lookups differ, as in C++ (an old-against-new comparison
/// of both lookups on every name, spelling and selector was run when the
/// tables replaced their three hand-written chains).
#[cfg(all(test, feature = "lua"))]
mod tests {
    use crate::modsecurity::ModSecurity;
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

        let seclang = |n: &str| new_variable(n, VariableSelector::None).map(|v| v.full_name().to_string());
        // RESOURCE: the persistent collection in SecLang, `setrsc`'s value
        // in Lua.
        assert_eq!(seclang("RESOURCE").as_deref(), Some("RESOURCE"));
        assert_eq!(string_match_resolve(&t, "RESOURCE").unwrap(), b"setrsc-value");
        // Six MULTIPART_* flags and STATUS are SecLang only.
        assert_eq!(seclang("multipart_lf_line").as_deref(), Some("MULTIPART_LF_LINE"));
        assert!(string_match_resolve(&t, "MULTIPART_LF_LINE").is_err());
        assert_eq!(seclang("STATUS_LINE").as_deref(), Some("STATUS"));
        assert!(string_match_resolve(&t, "STATUS").is_err());
        // Names of the C++ classes (sic).
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
