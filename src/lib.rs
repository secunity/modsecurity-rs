//! libmodsecurity v3, the ModSecurity web application firewall engine, in
//! Rust.
//!
//! The API is the handful of types re-exported here: a [`ModSecurity`]
//! engine instance, the [`RulesSet`] loaded from SecLang configuration,
//! and a [`Transaction`] per HTTP exchange, which the connector feeds phase
//! by phase and asks for an [`Intervention`]. The same engine is offered to
//! C as libmodsecurity's `msc_*` API by the `modsecurity-capi` crate.
//!
//! ```no_run
//! use modsecurity::{ModSecurity, RulesSet, Transaction};
//!
//! let modsec = ModSecurity::new();
//! let mut rules = RulesSet::new();
//! rules.load_from_uri("rules.conf").expect("valid rules");
//!
//! let mut transaction = Transaction::new(&modsec, &rules, None);
//! transaction.process_connection("127.0.0.1", 12345, "127.0.0.1", 80);
//! transaction.process_uri(b"/?q=1", b"GET", b"1.1");
//! transaction.add_request_header(b"Host", b"example.com");
//! transaction.process_request_headers();
//!
//! if let Some(it) = transaction.intervention() {
//!     println!("There is an intervention: status {}", it.status);
//! }
//! ```

// The calls into C libraries are in the `modsecurity-native` crate.
#![forbid(unsafe_code)]

/// Writes to the debug log of a transaction: the message is only formatted
/// when the configured debug level is high enough.
macro_rules! ms_dbg_a {
    ($t:expr, $lvl:expr, $($arg:tt)*) => {{
        let __t: &$crate::transaction::Transaction<'_> = &*$t;
        if __t.debug_enabled($lvl) {
            __t.debug($lvl, &format!($($arg)*));
        }
    }};
}

/// Same as [`ms_dbg_a`] for call sites where the transaction is optional
/// (the C++ macro tolerates a null transaction pointer).
macro_rules! ms_dbg_opt {
    ($t:expr, $lvl:expr, $($arg:tt)*) => {{
        if let Some(__t) = $t {
            $crate::ms_dbg_a!(__t, $lvl, $($arg)*);
        }
    }};
}

/// Writes to the debug log from an action (through its `ActionContext`):
/// the message is only formatted when the debug level is high enough.
macro_rules! act_dbg {
    ($cx:expr, $lvl:expr, $($arg:tt)*) => {{
        if $cx.debug_enabled($lvl) {
            $cx.debug($lvl, &format!($($arg)*));
        }
    }};
}

pub(crate) use {act_dbg, ms_dbg_a, ms_dbg_opt};

pub use crate::debug_log::DebugLog;
pub use crate::intervention::Intervention;
pub use crate::modsecurity::{
    INCLUDE_FULL_HIGHLIGHT_LOG_PROPERTY, MODSECURITY_MAJOR, MODSECURITY_MINOR, MODSECURITY_PATCHLEVEL,
    MODSECURITY_VERSION, ModSecLogCb, ModSecurity, RULE_MESSAGE_LOG_PROPERTY, ServerLogEntry, TEXT_LOG_PROPERTY,
};
pub use crate::rule::message::{CLIENT_LOG_MESSAGE_INFO, ERROR_LOG_TAIL_LOG_MESSAGE_INFO, RuleMessage};
pub use crate::rules_set::{LoadError, RulesSet};
pub use crate::transaction::Transaction;

pub(crate) mod actions;
pub(crate) mod anchored_set_variable;
pub(crate) mod anchored_set_variable_translation_proxy;
pub(crate) mod anchored_variable;
pub(crate) mod audit_log;
/// The collections (the `modsecurity-collections` crate).
pub(crate) use modsecurity_collections as collection;
pub(crate) mod debug_log;
pub(crate) mod engine;
#[cfg(feature = "http")]
mod http_support;
pub(crate) mod intervention;
#[cfg(feature = "tower")]
pub mod middleware;
pub(crate) mod modsecurity;
pub(crate) mod operators;
pub(crate) mod parser;
pub(crate) mod request_body_processor;
pub(crate) mod rule;
pub(crate) mod rules_set;
pub(crate) mod run_time_string;
pub(crate) mod transaction;
pub(crate) mod unique_id;
pub(crate) mod utils;
pub(crate) mod variables;
/// The resolved values and their origin (the `modsecurity-types` crate).
pub(crate) use modsecurity_types::{variable_origin, variable_value};

/// Internals the test utilities of this repository (`test/`, `tools/`,
/// `fuzz/`) drive directly. Not part of the API: they change without
/// notice.
#[doc(hidden)]
pub mod internal {
    pub use crate::actions::capture::Capture;
    pub use crate::actions::rule_action::RuleAction;
    pub use crate::actions::transformation::Transformation;
    pub use crate::operators::operator::{Operator, instantiate as instantiate_operator};
    pub use crate::rule::with_actions::{RuleWithActions, RuleWithActionsKind};
    pub use crate::utils::json::{JsonValue, parse_tree};
    pub use crate::utils::regex::Regex;
    pub use crate::utils::string::to_hex_if_needed;
    pub use modsecurity_operators::libinjection_adapter::{
        InjectionResult, clear_libinjection_overrides_for_testing, set_libinjection_sqli_override_for_testing,
        set_libinjection_xss_override_for_testing,
    };

    use crate::{DebugLog, RuleMessage, RulesSet, Transaction};

    /// Whether `op` matches `input`, evaluated alone for `rule` in `t`.
    pub fn evaluate_operator(
        op: &dyn Operator,
        t: &mut Transaction<'_>,
        rule: &RuleWithActions,
        input: &[u8],
        rm: &mut RuleMessage<'_>,
    ) -> bool {
        op.evaluate(&mut crate::operators::operator::MatchContext::new(t, rule, rm), input)
    }

    /// A rule message for `rule`, to evaluate an operator alone.
    pub fn new_rule_message(rule: &RuleWithActions) -> RuleMessage<'_> {
        RuleMessage::new(rule)
    }

    /// The value of `TX:key`.
    pub fn tx_value<'t>(t: &'t Transaction<'_>, key: &[u8]) -> Option<&'t [u8]> {
        t.collections.tx.get(key)
    }

    /// The debug log the rules were created with.
    pub fn debug_log(rules: &RulesSet) -> &dyn DebugLog {
        rules.properties.debug_log.as_ref()
    }

    /// The path of `SecAuditLog`.
    pub fn audit_log_path(rules: &RulesSet) -> &str {
        &rules.properties.audit_log.path1
    }

    /// Takes the parser errors collected so far.
    pub fn take_parser_error(rules: &mut RulesSet) -> String {
        std::mem::take(&mut rules.properties.parser_error)
    }
}

/// Connectors share one `ModSecurity` and one `RulesSet` between worker
/// threads and may move transactions between threads (as with the C++
/// library); keep those guarantees checked at compile time.
#[cfg(test)]
#[test]
fn thread_safety() {
    fn send_sync<T: Send + Sync>() {}
    fn send<T: Send>() {}
    send_sync::<modsecurity::ModSecurity>();
    send_sync::<rules_set::RulesSet>();
    send::<transaction::Transaction<'static>>();
}

/// Compiles the example of the README as a doctest.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
