//! The libinjection SQLi and XSS detectors, as `@detectSQLi` and
//! `@detectXSS` run them.
//!
//! libinjection is provided by the pure Rust `libinjection` crate
//! (vendored under `others/libinjection`). Its SQLi detector follows
//! libinjection's fingerprinting; its XSS detector is a different
//! (blocklist based) design, so `@detectXSS` verdicts can differ from the C
//! library on some inputs. The Rust detectors never report a parser error;
//! [`Detection::ParserError`] only comes from the overrides of the
//! [`testing`] module.

/// What a detector says about an input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Detection<F = ()> {
    /// No injection.
    Clean,
    /// An injection; for SQLi, with its libinjection fingerprint (e.g.
    /// `s&1o`).
    Attack(F),
    /// The detector's parser failed (`LIBINJECTION_RESULT_ERROR` in
    /// libinjection v4), handled in fail-safe mode as an attack.
    ParserError,
}

impl<F> Detection<F> {
    /// Whether the operator matches: on an attack and, to fail safe, on a
    /// parser error.
    pub fn is_malicious(&self) -> bool {
        !matches!(self, Detection::Clean)
    }

    /// The name of the result in the debug log.
    pub fn as_str(&self) -> &'static str {
        match self {
            Detection::Attack(_) => "attack-detected",
            Detection::Clean => "no-attack",
            Detection::ParserError => "parser-error",
        }
    }
}

/// Checks `input` for SQL injection.
pub fn detect_sqli(input: &[u8]) -> Detection<Vec<u8>> {
    if let Some(f) = testing::SQLI_OVERRIDE.get() {
        return f(input);
    }
    match ::libinjection::detect_sqli(input) {
        Some(finding) => Detection::Attack(finding.fingerprint.as_bytes().to_vec()),
        None => Detection::Clean,
    }
}

/// Checks `input` for cross-site scripting.
pub fn detect_xss(input: &[u8]) -> Detection {
    if let Some(f) = testing::XSS_OVERRIDE.get() {
        return f(input);
    }
    match ::libinjection::detect_xss(input) {
        Some(_) => Detection::Attack(()),
        None => Detection::Clean,
    }
}

/// The input as shown in the libinjection debug messages: hex escaped and
/// limited to 80 characters. Only built when such a message is logged.
pub(crate) fn loggable_input(input: &[u8]) -> String {
    use modsecurity_compat::chars::{limit_to, to_hex_if_needed};
    String::from_utf8_lossy(&limit_to(80, to_hex_if_needed(input, false).as_bytes())).into_owned()
}

/// Replacing the detectors of the current thread, for the tests (the unit
/// suite forces parser errors with them: `operator-libinjection-error`).
/// Not part of the API.
#[doc(hidden)]
pub mod testing {
    use super::Detection;
    use std::cell::Cell;

    /// An SQLi detector.
    pub type DetectSQLiFn = fn(&[u8]) -> Detection<Vec<u8>>;
    /// An XSS detector.
    pub type DetectXSSFn = fn(&[u8]) -> Detection;

    thread_local! {
        pub(super) static SQLI_OVERRIDE: Cell<Option<DetectSQLiFn>> = const { Cell::new(None) };
        pub(super) static XSS_OVERRIDE: Cell<Option<DetectXSSFn>> = const { Cell::new(None) };
    }

    /// `@detectSQLi` uses `f` on this thread until [`clear_overrides`].
    pub fn override_sqli(f: DetectSQLiFn) {
        SQLI_OVERRIDE.set(Some(f));
    }

    /// `@detectXSS` uses `f` on this thread until [`clear_overrides`].
    pub fn override_xss(f: DetectXSSFn) {
        XSS_OVERRIDE.set(Some(f));
    }

    /// Both operators use libinjection again on this thread.
    pub fn clear_overrides() {
        SQLI_OVERRIDE.set(None);
        XSS_OVERRIDE.set(None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::eval;
    use crate::{detect_sqli::DetectSQLi, detect_xss::DetectXSS};

    #[test]
    fn detectors_and_overrides() {
        assert_eq!(detect_sqli(b"1' OR '1'='1"), Detection::Attack(b"s&sos".to_vec()));
        assert_eq!(detect_sqli(b"hello"), Detection::Clean);
        assert!(detect_xss(b"<script>alert(1)</script>").is_malicious());

        testing::override_sqli(|_| Detection::ParserError);
        testing::override_xss(|_| Detection::ParserError);
        assert!(eval(&DetectSQLi::new(), b"hello"));
        assert!(eval(&DetectXSS::new(), b"hello"));
        testing::clear_overrides();
        assert!(!eval(&DetectSQLi::new(), b"hello"));
        assert!(!eval(&DetectXSS::new(), b"hello"));
    }
}
