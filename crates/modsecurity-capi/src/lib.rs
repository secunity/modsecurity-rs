//! The libmodsecurity C API: the `msc_*` functions, with the C structures and
//! memory conventions of `modsecurity/modsecurity.h`, `rules_set.h` and
//! `transaction.h`.
//!
//! This is where Rust meets C callers: raw pointers are checked and turned
//! into references here, and the engine (the `modsecurity` crate) is used
//! through its Rust API.

pub mod intervention;
pub mod modsecurity;
pub mod rules_set;
pub mod transaction;
