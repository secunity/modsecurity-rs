//! The operators: the engine's [`operator::Operator`] trait, behind which
//! the matchers of the `modsecurity-operators` crate run, and the two
//! operators that are part of the engine itself: `@geoLookup` and
//! `@inspectFile` (they need the transaction).

pub mod geo_lookup;
pub mod inspect_file;
pub mod operator;
