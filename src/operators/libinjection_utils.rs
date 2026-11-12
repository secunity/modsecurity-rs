//! Port of `src/operators/libinjection_utils.h`.

/// `injection_result_t` (libinjection v4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectionResult {
    False,
    True,
    Error,
}

/// libinjection parser errors are handled in fail-safe mode as suspicious
/// results, so callers can block on both confirmed detections and parser
/// failures.
pub fn is_malicious_libinjection_result(result: InjectionResult) -> bool {
    result == InjectionResult::True || result == InjectionResult::Error
}

pub fn libinjection_result_to_string(result: InjectionResult) -> &'static str {
    match result {
        InjectionResult::True => "attack-detected",
        InjectionResult::False => "no-attack",
        InjectionResult::Error => "parser-error",
    }
}

/// The input as shown in the libinjection debug messages: hex escaped and
/// limited to 80 characters. Only built when such a message is logged.
pub fn loggable_input(input: &[u8]) -> String {
    use crate::utils::string::{limit_to, to_hex_if_needed};
    String::from_utf8_lossy(&limit_to(80, to_hex_if_needed(input, false).as_bytes())).into_owned()
}
