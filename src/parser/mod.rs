//! `parser`: reading SecLang configurations.

#[cfg(feature = "pest-parser")]
mod build;
pub mod driver;
#[cfg(all(test, feature = "pest-parser"))]
mod equivalence;
// With `pest-parser`, the port of the C++ flex/bison parser is only used by
// the equivalence tests, until it is removed.
#[cfg_attr(feature = "pest-parser", allow(dead_code))]
pub mod seclang_parser;
#[cfg_attr(feature = "pest-parser", allow(dead_code))]
pub mod seclang_scanner;
#[cfg(feature = "pest-parser")]
pub mod syntax;
