//! Port of `src/operators/libinjection_adapter.h` /
//! `src/operators/libinjection_adapter.cc`.
//!
//! libinjection is provided by the pure Rust `libinjection` crate
//! (vendored under `others/libinjection`). Its SQLi detector follows
//! libinjection's fingerprinting; its XSS detector is a different
//! (blocklist based) design, so `@detectXSS` verdicts can differ from the C
//! library on some inputs. The Rust detectors never report a parser error;
//! [`InjectionResult::Error`] only comes from the test overrides.

use std::cell::Cell;

pub use crate::operators::libinjection_utils::InjectionResult;

/// `DetectSQLiFn`: input, fingerprint out-parameter.
pub type DetectSQLiFn = fn(&[u8], &mut Vec<u8>) -> InjectionResult;
/// `DetectXSSFn`
pub type DetectXSSFn = fn(&[u8]) -> InjectionResult;

thread_local! {
    // Per-thread overrides avoid cross-thread interference during tests.
    static SQLI_OVERRIDE: Cell<Option<DetectSQLiFn>> = const { Cell::new(None) };
    static XSS_OVERRIDE: Cell<Option<DetectXSSFn>> = const { Cell::new(None) };
}

/// `runLibinjectionSQLi`: on detection `fingerprint` receives the
/// libinjection fingerprint (e.g. `s&1o`).
pub fn run_libinjection_sqli(input: &[u8], fingerprint: &mut Vec<u8>) -> InjectionResult {
    if let Some(f) = SQLI_OVERRIDE.with(|c| c.get()) {
        return f(input, fingerprint);
    }
    fingerprint.clear();
    match libinjection::detect_sqli(input) {
        Some(finding) => {
            fingerprint.extend_from_slice(finding.fingerprint.as_bytes());
            InjectionResult::True
        }
        None => InjectionResult::False,
    }
}

/// `runLibinjectionXSS`
pub fn run_libinjection_xss(input: &[u8]) -> InjectionResult {
    if let Some(f) = XSS_OVERRIDE.with(|c| c.get()) {
        return f(input);
    }
    match libinjection::detect_xss(input) {
        Some(_) => InjectionResult::True,
        None => InjectionResult::False,
    }
}

/// Test-only hook.
pub fn set_libinjection_sqli_override_for_testing(f: DetectSQLiFn) {
    SQLI_OVERRIDE.with(|c| c.set(Some(f)));
}

/// Test-only hook.
pub fn set_libinjection_xss_override_for_testing(f: DetectXSSFn) {
    XSS_OVERRIDE.with(|c| c.set(Some(f)));
}

pub fn clear_libinjection_overrides_for_testing() {
    SQLI_OVERRIDE.with(|c| c.set(None));
    XSS_OVERRIDE.with(|c| c.set(None));
}
