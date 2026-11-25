//! The operators as SecLang names them (`@rx`, `@pmFromFile`, ...): the
//! table the configuration parser consults.
//!
//! It differs from [`instantiate`](crate::instantiate), which looks an
//! operator up by its own name: here `@pmf` is `@pmFromFile` (which
//! `instantiate` builds for `pmf` too, but named `PmFromF` in messages),
//! `@noMatch` is not a SecLang operator, and `@validateHash`, `@gsbLookup`
//! and `@rsub` are recognised but rejected.
//! It also names the operator the engine implements (`@inspectFile`).

/// An operator of the SecLang grammar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecLangOperator {
    /// The name to build it by (`instantiate`), also shown in error
    /// messages; empty for the ones not supported.
    pub name: &'static str,
    /// Whether it takes a parameter.
    pub takes_param: bool,
    /// For an operator the grammar recognises but the library does not
    /// support: its name in the "not yet supported" error.
    pub not_supported: Option<&'static str>,
}

/// The operator `@name` (`name` without the `@`, case insensitive), or
/// `None` when SecLang has no such operator.
pub fn seclang_operator(name: &str) -> Option<SecLangOperator> {
    let op = |name, takes_param| Some(SecLangOperator { name, takes_param, not_supported: None });
    let unsupported = |n| Some(SecLangOperator { name: "", takes_param: true, not_supported: Some(n) });
    match name.to_ascii_lowercase().as_str() {
        "unconditionalmatch" => op("unconditionalMatch", false),
        "detectsqli" => op("detectSQLi", false),
        "detectxss" => op("detectXSS", false),
        "validateurlencoding" => op("validateUrlEncoding", false),
        "validateutf8encoding" => op("validateUtf8Encoding", false),
        "geolookup" => op("geoLookup", false),
        "inspectfile" => op("inspectFile", true),
        "fuzzyhash" => op("fuzzyHash", true),
        "validatebyterange" => op("validateByteRange", true),
        "validatedtd" => op("validateDTD", true),
        "validatehash" => unsupported("ValidateHash"),
        "validateschema" => op("validateSchema", true),
        "verifycc" => op("verifyCC", true),
        "verifycpf" => op("verifyCPF", true),
        "verifyssn" => op("verifySSN", true),
        "verifysvnr" => op("verifySVNR", true),
        "gsblookup" => unsupported("GsbLookup"),
        "rsub" => unsupported("Rsub"),
        "within" => op("within", true),
        "containsword" => op("containsWord", true),
        "contains" => op("contains", true),
        "endswith" => op("endsWith", true),
        "eq" => op("eq", true),
        "ge" => op("ge", true),
        "gt" => op("gt", true),
        // `@ipMatchF` is an alias of `@ipMatchFromFile`.
        "ipmatchf" | "ipmatchfromfile" => op("ipMatchF", true),
        "ipmatch" => op("ipMatch", true),
        "le" => op("le", true),
        "lt" => op("lt", true),
        // Both `@pmf` and `@pmFromFile` build a `PmFromFile`.
        "pmf" | "pmfromfile" => op("pmFromFile", true),
        "pm" => op("pm", true),
        "rbl" => op("rbl", true),
        "rx" => op("rx", true),
        "rxglobal" => op("rxGlobal", true),
        "streq" => op("streq", true),
        "strmatch" => op("strmatch", true),
        "beginswith" => op("beginsWith", true),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every operator the grammar accepts can be built, by this crate or
    /// (`@inspectFile`) by the engine.
    #[test]
    fn grammar_operators_are_built_by_instantiate() {
        let names = [
            "unconditionalMatch",
            "detectSQLi",
            "detectXSS",
            "validateUrlEncoding",
            "validateUtf8Encoding",
            "geoLookup",
            "inspectFile",
            "fuzzyHash",
            "validateByteRange",
            "validateDTD",
            "validateHash",
            "validateSchema",
            "verifyCC",
            "verifyCPF",
            "verifySSN",
            "verifySVNR",
            "gsbLookup",
            "rsub",
            "within",
            "containsWord",
            "contains",
            "endsWith",
            "eq",
            "ge",
            "gt",
            "ipMatchF",
            "ipMatchFromFile",
            "ipMatch",
            "le",
            "lt",
            "pmf",
            "pmFromFile",
            "pm",
            "rbl",
            "rx",
            "rxGlobal",
            "streq",
            "strmatch",
            "beginsWith",
        ];
        for n in names {
            let op = seclang_operator(n).unwrap_or_else(|| panic!("{n}"));
            assert_eq!(seclang_operator(&n.to_ascii_uppercase()), Some(op));
            if op.not_supported.is_some() || op.name == "inspectFile" {
                continue;
            }
            let param = crate::Param::from_text("1");
            assert!(crate::instantiate(op.name, param, "", &crate::test_support::LocalFiles).is_some(), "{n}");
        }
        assert_eq!(seclang_operator("pmf").unwrap().name, "pmFromFile");
        assert_eq!(seclang_operator("validateHash").unwrap().not_supported, Some("ValidateHash"));
        assert_eq!(seclang_operator("noMatch"), None);
        assert_eq!(seclang_operator("nosuch"), None);
    }
}
