//! libmodsecurity v3, ported from C++ to Rust.
//!
//! The module tree mirrors the C++ source tree: every `src/<dir>/<file>.cc`
//! (together with its header) became `src/<dir>/<file>.rs`, and the public
//! headers under `headers/modsecurity/` became the modules at the crate root
//! (or, for `actions/`, `collection/`, `audit_log.h` and `debug_log.h`, the
//! module of the same name in the matching directory).
//!
//! Example usage (compare with the `@mainpage` example of `modsecurity.h`):
//!
//! ```no_run
//! use modsecurity::modsecurity::ModSecurity;
//! use modsecurity::rules_set::RulesSet;
//! use modsecurity::transaction::Transaction;
//! use modsecurity::intervention::ModSecurityIntervention;
//!
//! let modsec = ModSecurity::new();
//! let mut rules = RulesSet::new();
//! rules.load_from_uri("rules.conf");
//!
//! let mut transaction = Transaction::new(&modsec, &rules, None);
//! transaction.process_connection("127.0.0.1", 12345, "127.0.0.1", 80);
//!
//! let mut it = ModSecurityIntervention::default();
//! if transaction.intervention(&mut it) {
//!     println!("There is an intervention");
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
pub mod anchored_set_variable;
pub mod anchored_set_variable_translation_proxy;
pub mod anchored_variable;
pub mod audit_log;
pub mod collection;
pub mod debug_log;
pub mod engine;
pub mod intervention;
pub mod modsecurity;
pub mod operators;
pub mod parser;
pub mod request_body_processor;
pub mod rule;
pub mod rule_marker;
pub mod rule_message;
pub mod rule_script;
pub mod rule_unconditional;
pub mod rule_with_actions;
pub mod rule_with_operator;
pub mod rules;
pub mod rules_exceptions;
pub mod rules_set;
pub mod rules_set_phases;
pub mod rules_set_properties;
pub mod run_time_string;
pub mod transaction;
pub mod unique_id;
pub mod utils;
pub mod variable_origin;
pub mod variable_value;
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
