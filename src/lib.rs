//! libmodsecurity v3, ported from C++ to Rust.
//!
//! Modules separate configuration parsing, rule evaluation, transactions,
//! collections, body processors and logging. The initial port followed the
//! C++ source layout; internal Rust representations can evolve independently
//! while preserving SecLang behaviour and the `msc_*` C API.
//!
//! Example usage (compare with the `@mainpage` example of `modsecurity.h`):
//!
//! ```no_run
//! use modsecurity::modsecurity::ModSecurity;
//! use modsecurity::rules_set::RulesSet;
//! use modsecurity::transaction::Transaction;
//!
//! let modsec = ModSecurity::new();
//! let mut rules = RulesSet::new();
//! rules.load_from_uri("rules.conf");
//!
//! let mut transaction = Transaction::new(&modsec, &rules, None);
//! transaction.process_connection("127.0.0.1", 12345, "127.0.0.1", 80);
//!
//! if let Some(it) = transaction.intervention() {
//!     println!("There is an intervention: status {}", it.status);
//! }
//! ```

/// Debug-log helper equivalent to the C++ `ms_dbg_a(t, level, msg)` macro:
/// the message is only formatted when the configured debug level is high
/// enough.
#[macro_export]
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
#[macro_export]
macro_rules! ms_dbg_opt {
    ($t:expr, $lvl:expr, $($arg:tt)*) => {{
        if let Some(__t) = $t {
            $crate::ms_dbg_a!(__t, $lvl, $($arg)*);
        }
    }};
}

pub mod actions;
pub(crate) mod anchored_set_variable;
pub(crate) mod anchored_set_variable_translation_proxy;
pub(crate) mod anchored_variable;
pub(crate) mod audit_log;
pub mod collection;
pub mod debug_log;
pub(crate) mod engine;
pub mod intervention;
pub mod modsecurity;
pub mod operators;
pub(crate) mod parser;
pub(crate) mod request_body_processor;
pub(crate) mod rule;
pub(crate) mod rule_marker;
pub mod rule_message;
pub(crate) mod rule_script;
pub(crate) mod rule_unconditional;
pub mod rule_with_actions;
pub(crate) mod rule_with_operator;
pub(crate) mod rules_exceptions;
pub mod rules_set;
pub(crate) mod rules_set_phases;
pub(crate) mod rules_set_properties;
pub(crate) mod run_time_string;
pub mod transaction;
pub(crate) mod unique_id;
pub mod utils;
pub(crate) mod variable_origin;
pub(crate) mod variable_value;
pub mod variables;

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
