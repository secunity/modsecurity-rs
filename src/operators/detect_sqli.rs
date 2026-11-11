//! Port of `src/operators/detect_sqli.cc`, `src/operators/detect_sqli.h`.

use crate::collection::collection::Collection;
use crate::operators::libinjection_adapter::run_libinjection_sqli;
use crate::operators::libinjection_utils::{
    InjectionResult, is_malicious_libinjection_result, libinjection_result_to_string,
};
use crate::operators::operator::{Operator, OperatorBase};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;
use crate::utils::string::{limit_to, to_hex_if_needed};

#[derive(Debug)]
pub struct DetectSQLi {
    pub base: OperatorBase,
}

impl Default for DetectSQLi {
    fn default() -> Self {
        Self::new()
    }
}

impl DetectSQLi {
    pub fn new() -> Self {
        let mut base = OperatorBase::new("DetectSQLi");
        base.match_message = "detected SQLi using libinjection.".to_string();
        DetectSQLi { base }
    }
}

impl Operator for DetectSQLi {
    crate::operator_base_accessors!();
    fn evaluate(
        &self,
        t: Option<&mut Transaction<'_>>,
        rule: Option<&RuleWithActions>,
        input: &[u8],
        _rm: Option<&mut RuleMessage<'_>>,
    ) -> bool {
        let loggable_input =
            String::from_utf8_lossy(&limit_to(80, to_hex_if_needed(input, false).as_bytes())).into_owned();

        let mut fingerprint = Vec::new();
        let sqli_result = run_libinjection_sqli(input, &mut fingerprint);
        // The C++ fingerprint is a NUL terminated char array.
        if let Some(p) = fingerprint.iter().position(|&c| c == 0) {
            fingerprint.truncate(p);
        }

        let Some(t) = t else {
            return is_malicious_libinjection_result(sqli_result);
        };

        match sqli_result {
            InjectionResult::True => {
                t.matched.push(fingerprint.clone());

                crate::ms_dbg_a!(
                    t,
                    4,
                    "detected SQLi using libinjection with fingerprint '{}' at: '{}'",
                    String::from_utf8_lossy(&fingerprint),
                    loggable_input
                );

                if rule.is_some_and(|r| r.has_capture_action()) {
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
                    loggable_input
                );

                if rule.is_some_and(|r| r.has_capture_action()) {
                    t.collections.tx_collection.store_or_update_first(b"0", input);
                    crate::ms_dbg_a!(t, 7, "Added DetectSQLi error input TX.0: {}", String::from_utf8_lossy(input));
                }

                // Keep `matched` untouched for parser-error paths to avoid
                // introducing synthetic fingerprints for non-TRUE results.
            }
            InjectionResult::False => {
                crate::ms_dbg_a!(t, 9, "libinjection was not able to find any SQLi in: {}", loggable_input);
            }
        }

        is_malicious_libinjection_result(sqli_result)
    }
}
