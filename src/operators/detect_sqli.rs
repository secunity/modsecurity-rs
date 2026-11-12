//! Port of `src/operators/detect_sqli.cc`, `src/operators/detect_sqli.h`.

use crate::collection::collection::Collection;
use crate::operators::libinjection_adapter::run_libinjection_sqli;
use crate::operators::libinjection_utils::{
    InjectionResult, is_malicious_libinjection_result, libinjection_result_to_string, loggable_input,
};
use crate::operators::operator::Operator;
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct DetectSQLi;

impl Default for DetectSQLi {
    fn default() -> Self {
        Self::new()
    }
}

impl DetectSQLi {
    pub fn new() -> Self {
        DetectSQLi
    }
}

impl Operator for DetectSQLi {
    fn name(&self) -> &'static str {
        "DetectSQLi"
    }

    fn resolve_match_message(&self, _t: &Transaction<'_>, _key: &[u8], _value: &[u8]) -> Vec<u8> {
        b"detected SQLi using libinjection.".to_vec()
    }
    fn evaluate(
        &self,
        t: &mut Transaction<'_>,
        rule: &RuleWithActions,
        input: &[u8],
        _rm: &mut RuleMessage<'_>,
    ) -> bool {
        let mut fingerprint = Vec::new();
        let sqli_result = run_libinjection_sqli(input, &mut fingerprint);
        // The C++ fingerprint is a NUL terminated char array.
        if let Some(p) = fingerprint.iter().position(|&c| c == 0) {
            fingerprint.truncate(p);
        }

        match sqli_result {
            InjectionResult::True => {
                t.matched.push(fingerprint.clone());

                crate::ms_dbg_a!(
                    t,
                    4,
                    "detected SQLi using libinjection with fingerprint '{}' at: '{}'",
                    String::from_utf8_lossy(&fingerprint),
                    loggable_input(input)
                );

                if rule.has_capture_action() {
                    t.collections.tx_collection.store_or_update_first(b"0", &fingerprint);
                    crate::ms_dbg_a!(t, 7, "Added DetectSQLi match TX.0: {}", String::from_utf8_lossy(&fingerprint));
                }
            }
            InjectionResult::Error => {
                crate::ms_dbg_a!(
                    t,
                    4,
                    "libinjection parser error during SQLi analysis ({}); treating as match (fail-safe). Input: '{}'",
                    libinjection_result_to_string(sqli_result),
                    loggable_input(input)
                );

                if rule.has_capture_action() {
                    t.collections.tx_collection.store_or_update_first(b"0", input);
                    crate::ms_dbg_a!(t, 7, "Added DetectSQLi error input TX.0: {}", String::from_utf8_lossy(input));
                }

                // Keep `matched` untouched for parser-error paths to avoid
                // introducing synthetic fingerprints for non-TRUE results.
            }
            InjectionResult::False => {
                crate::ms_dbg_a!(t, 9, "libinjection was not able to find any SQLi in: {}", loggable_input(input));
            }
        }

        is_malicious_libinjection_result(sqli_result)
    }
}
