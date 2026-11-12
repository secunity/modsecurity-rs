//! Port of `src/operators/detect_xss.cc`, `src/operators/detect_xss.h`.

use crate::collection::Collection;
use crate::operators::libinjection_adapter::run_libinjection_xss;
use crate::operators::libinjection_utils::{
    InjectionResult, is_malicious_libinjection_result, libinjection_result_to_string, loggable_input,
};
use crate::operators::operator::Operator;
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct DetectXSS;

impl Default for DetectXSS {
    fn default() -> Self {
        Self::new()
    }
}

impl DetectXSS {
    pub fn new() -> Self {
        DetectXSS
    }
}

impl Operator for DetectXSS {
    fn name(&self) -> &'static str {
        "DetectXSS"
    }

    fn resolve_match_message(&self, _t: &Transaction<'_>, _key: &[u8], _value: &[u8]) -> Vec<u8> {
        b"detected XSS using libinjection.".to_vec()
    }
    fn evaluate(
        &self,
        t: &mut Transaction<'_>,
        rule: &RuleWithActions,
        input: &[u8],
        _rm: &mut RuleMessage<'_>,
    ) -> bool {
        let xss_result = run_libinjection_xss(input);

        match xss_result {
            InjectionResult::True => {
                crate::ms_dbg_a!(t, 5, "detected XSS using libinjection.");
                if rule.has_capture_action() {
                    t.collections.tx_collection.store_or_update_first(b"0", input);
                    crate::ms_dbg_a!(t, 7, "Added DetectXSS match TX.0: {}", String::from_utf8_lossy(input));
                }
            }
            InjectionResult::Error => {
                crate::ms_dbg_a!(
                    t,
                    4,
                    "libinjection parser error during XSS analysis ({}); treating as match (fail-safe). Input: {}",
                    libinjection_result_to_string(xss_result),
                    loggable_input(input)
                );
                if rule.has_capture_action() {
                    t.collections.tx_collection.store_or_update_first(b"0", input);
                    crate::ms_dbg_a!(t, 7, "Added DetectXSS error input TX.0: {}", String::from_utf8_lossy(input));
                }
            }
            InjectionResult::False => {
                crate::ms_dbg_a!(t, 9, "libinjection was not able to find any XSS in: {}", loggable_input(input));
            }
        }

        is_malicious_libinjection_result(xss_result)
    }
}
