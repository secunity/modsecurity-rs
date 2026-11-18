//! The `@detectSQLi` operator: detects SQL injection with libinjection.

use crate::libinjection_adapter::run_libinjection_sqli;
use crate::libinjection_utils::{
    InjectionResult, is_malicious_libinjection_result, libinjection_result_to_string, loggable_input,
};
use crate::{Context, Operator};

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

    fn resolve_match_message(&self, _param: &[u8], _key: &[u8], _value: &[u8]) -> Vec<u8> {
        b"detected SQLi using libinjection.".to_vec()
    }
    fn evaluate(&self, cx: &mut dyn Context, input: &[u8]) -> bool {
        let mut fingerprint = Vec::new();
        let sqli_result = run_libinjection_sqli(input, &mut fingerprint);
        // The C++ fingerprint is a NUL terminated char array.
        fingerprint.truncate(modsecurity_compat::chars::c_str(&fingerprint).len());

        match sqli_result {
            InjectionResult::True => {
                cx.matched(fingerprint.clone());

                crate::ms_dbg!(
                    cx,
                    4,
                    "detected SQLi using libinjection with fingerprint '{}' at: '{}'",
                    String::from_utf8_lossy(&fingerprint),
                    loggable_input(input)
                );

                if cx.captures() {
                    cx.set_capture(b"0", fingerprint.clone());
                    crate::ms_dbg!(cx, 7, "Added DetectSQLi match TX.0: {}", String::from_utf8_lossy(&fingerprint));
                }
            }
            InjectionResult::Error => {
                crate::ms_dbg!(
                    cx,
                    4,
                    "libinjection parser error during SQLi analysis ({}); treating as match (fail-safe). Input: '{}'",
                    libinjection_result_to_string(sqli_result),
                    loggable_input(input)
                );

                if cx.captures() {
                    cx.set_capture(b"0", input.to_vec());
                    crate::ms_dbg!(cx, 7, "Added DetectSQLi error input TX.0: {}", String::from_utf8_lossy(input));
                }

                // Keep `matched` untouched for parser-error paths to avoid
                // introducing synthetic fingerprints for non-TRUE results.
            }
            InjectionResult::False => {
                crate::ms_dbg!(cx, 9, "libinjection was not able to find any SQLi in: {}", loggable_input(input));
            }
        }

        is_malicious_libinjection_result(sqli_result)
    }
}
