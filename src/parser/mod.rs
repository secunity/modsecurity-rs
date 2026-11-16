//! `parser`: reading SecLang configurations.
//!
//! The `modsecurity-seclang` crate reads the text into a syntax tree
//! (`syntax`), and `build.rs` applies its directives to a `Driver`
//! (`settings.rs` has the directives that are a keyword and a value).

mod build;
pub mod driver;
mod settings;
#[cfg(test)]
mod tests;

pub use modsecurity_seclang as syntax;
