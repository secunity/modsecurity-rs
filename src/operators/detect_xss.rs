//! Port of `src/operators/detect_xss.cc`, `src/operators/detect_xss.h`.

use crate::collection::collection::Collection;
use crate::operators::libinjection_adapter::run_libinjection_xss;
use crate::operators::libinjection_utils::{
    InjectionResult, is_malicious_libinjection_result, libinjection_result_to_string,
};
use crate::operators::operator::{Operator, OperatorBase};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;
use crate::utils::string::{limit_to, to_hex_if_needed};

#[derive(Debug)]
pub struct DetectXSS {
    pub base: OperatorBase,
}

impl Default for DetectXSS {
    fn default() -> Self {
        Self::new()
    }
}

impl DetectXSS {
    pub fn new() -> Self {
        let mut base = OperatorBase::new("DetectXSS");
        base.match_message = "detected XSS using libinjection.".to_string();
        DetectXSS { base }
    }
}

impl Operator for DetectXSS {
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

        let xss_result = run_libinjection_xss(input);

        let Some(t) = t else {
            return is_malicious_libinjection_result(xss_result);
        };

        match xss_result {
            InjectionResult::True => {
                crate::ms_dbg_a!(t, 5, "detected XSS using libinjection.");
                if rule.is_some_and(|r| r.has_capture_action()) {
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
                    loggable_input
                );
                if rule.is_some_and(|r| r.has_capture_action()) {
                    t.collections.tx_collection.store_or_update_first(b"0", input);
                    crate::ms_dbg_a!(t, 7, "Added DetectXSS error input TX.0: {}", String::from_utf8_lossy(input));
                }
            }
            InjectionResult::False => {
                crate::ms_dbg_a!(t, 9, "libinjection was not able to find any XSS in: {}", loggable_input);
            }
        }

        is_malicious_libinjection_result(xss_result)
    }
}
