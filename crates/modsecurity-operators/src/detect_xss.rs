//! The `@detectXSS` operator: detects cross-site scripting with
//! libinjection.

use crate::libinjection_adapter::{Detection, detect_xss, loggable_input};
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
        let detection = detect_xss(input);

        match detection {
            Detection::Attack(()) => {
                crate::ms_dbg!(cx, 5, "detected XSS using libinjection.");
                if cx.captures() {
                    cx.set_capture(b"0", input.to_vec());
                    crate::ms_dbg!(cx, 7, "Added DetectXSS match TX.0: {}", String::from_utf8_lossy(input));
                }
            }
            Detection::ParserError => {
                crate::ms_dbg!(
                    cx,
                    4,
                    "libinjection parser error during XSS analysis ({}); treating as match (fail-safe). Input: {}",
                    detection.as_str(),
                    loggable_input(input)
                );
                if cx.captures() {
                    cx.set_capture(b"0", input.to_vec());
                    crate::ms_dbg!(cx, 7, "Added DetectXSS error input TX.0: {}", String::from_utf8_lossy(input));
                }
            }
            Detection::Clean => {
                crate::ms_dbg!(cx, 9, "libinjection was not able to find any XSS in: {}", loggable_input(input));
            }
        }

        detection.is_malicious()
    }
}
