//! The `@detectSQLi` operator: detects SQL injection with libinjection.

use crate::libinjection_adapter::{Detection, detect_sqli, loggable_input};
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
        let detection = detect_sqli(input);
        let (malicious, result) = (detection.is_malicious(), detection.as_str());

        match detection {
            Detection::Attack(fingerprint) => {
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
                cx.matched(fingerprint);
            }
            Detection::ParserError => {
                crate::ms_dbg!(
                    cx,
                    4,
                    "libinjection parser error during SQLi analysis ({}); treating as match (fail-safe). Input: '{}'",
                    result,
                    loggable_input(input)
                );

                if cx.captures() {
                    cx.set_capture(b"0", input.to_vec());
                    crate::ms_dbg!(cx, 7, "Added DetectSQLi error input TX.0: {}", String::from_utf8_lossy(input));
                }

                // A parser error has no fingerprint: nothing is recorded as
                // matched.
            }
            Detection::Clean => {
                crate::ms_dbg!(cx, 9, "libinjection was not able to find any SQLi in: {}", loggable_input(input));
            }
        }

        malicious
    }
}
