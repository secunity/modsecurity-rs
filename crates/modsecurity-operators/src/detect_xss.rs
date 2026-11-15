//! The `@detectXSS` operator: detects cross-site scripting with
//! libinjection.

use crate::libinjection_adapter::run_libinjection_xss;
use crate::libinjection_utils::{
    InjectionResult, is_malicious_libinjection_result, libinjection_result_to_string, loggable_input,
};
use crate::{Context, Operator};

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

    fn resolve_match_message(&self, _param: &[u8], _key: &[u8], _value: &[u8]) -> Vec<u8> {
        b"detected XSS using libinjection.".to_vec()
    }
    fn evaluate(&self, cx: &mut dyn Context, input: &[u8]) -> bool {
        let xss_result = run_libinjection_xss(input);

        match xss_result {
            InjectionResult::True => {
                crate::op_dbg!(cx, 5, "detected XSS using libinjection.");
                if cx.captures() {
                    cx.set_capture(b"0", input.to_vec());
                    crate::op_dbg!(cx, 7, "Added DetectXSS match TX.0: {}", String::from_utf8_lossy(input));
                }
            }
            InjectionResult::Error => {
                crate::op_dbg!(
                    cx,
                    4,
                    "libinjection parser error during XSS analysis ({}); treating as match (fail-safe). Input: {}",
                    libinjection_result_to_string(xss_result),
                    loggable_input(input)
                );
                if cx.captures() {
                    cx.set_capture(b"0", input.to_vec());
                    crate::op_dbg!(cx, 7, "Added DetectXSS error input TX.0: {}", String::from_utf8_lossy(input));
                }
            }
            InjectionResult::False => {
                crate::op_dbg!(cx, 9, "libinjection was not able to find any XSS in: {}", loggable_input(input));
            }
        }

        is_malicious_libinjection_result(xss_result)
    }
}
