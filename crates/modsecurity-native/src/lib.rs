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

/// `s` up to its first NUL byte: what a C function is given of it. (The
/// engine's own copy is `modsecurity_compat::chars::c_str`; this crate is
/// below that one.)
#[allow(dead_code)]
pub(crate) fn c_str(s: &[u8]) -> &[u8] {
    match s.iter().position(|&c| c == 0) {
        Some(end) => &s[..end],
        None => s,
    }
}
