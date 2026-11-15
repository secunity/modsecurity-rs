//! `parser`: reading SecLang configurations.
//!
//! The `modsecurity-seclang` crate reads the text into a syntax tree
//! (`syntax`), and `build.rs` applies its directives to a `Driver`.

mod build;
pub mod driver;
#[cfg(test)]
mod tests;

pub use modsecurity_seclang as syntax;
