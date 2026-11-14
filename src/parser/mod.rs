//! `parser`: reading SecLang configurations.
//!
//! `seclang.pest` is the grammar, `syntax.rs` reads it into a syntax tree and
//! `build.rs` applies the directives to a `Driver`.

mod build;
pub mod driver;
pub mod syntax;
#[cfg(test)]
mod tests;
