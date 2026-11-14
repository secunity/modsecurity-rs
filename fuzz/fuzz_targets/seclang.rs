//! Loads arbitrary bytes as a SecLang configuration.
//!
//! Directives that read or write files, or use the network, are skipped
//! (`Include`, logs, `...FromFile`, scripts, ...): a configuration that
//! names one is not loaded.

#![no_main]

use libfuzzer_sys::fuzz_target;
use modsecurity::rules_set::RulesSet;

/// Words (lower case) of the directives, operators and actions that touch
/// files or the network when a configuration is loaded.
const OUTSIDE: &[&str] = &[
    "include",
    "remoterules",
    "debuglog",
    "auditlog",
    "geolookupdb",
    "unicodemapfile",
    "fromfile",
    "ipmatchf",
    "@pmf",
    "inspectfile",
    "exec",
    "rulescript",
    "validatedtd",
    "validateschema",
    "uploaddir",
    "datadir",
    "tmpdir",
    "fuzzyhash",
];

fuzz_target!(|data: &[u8]| {
    let lower = data.to_ascii_lowercase();
    if OUTSIDE.iter().any(|w| lower.windows(w.len()).any(|x| x == w.as_bytes())) {
        return;
    }
    let text = String::from_utf8_lossy(data);
    let mut rules = RulesSet::new();
    let _ = rules.load_with_ref(&text, "fuzz");
});
