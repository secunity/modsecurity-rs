//! The C libraries the ModSecurity engine uses, behind safe Rust APIs.
//!
//! All the `unsafe` code of the engine lives here: the engine crate
//! (`modsecurity`) forbids it. Each module wraps one library and states,
//! next to every `unsafe` block, why the call is sound.

pub mod posix;
pub mod regex;

#[cfg(feature = "libxml2")]
pub mod libxml2;
#[cfg(feature = "lmdb")]
pub mod lmdb;
#[cfg(feature = "lua")]
pub mod lua;
#[cfg(feature = "ssdeep")]
pub mod ssdeep;

#[cfg(feature = "testing")]
pub mod testing;
