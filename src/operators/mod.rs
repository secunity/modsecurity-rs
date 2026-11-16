//! The operators: [`operator::Operator`] is a matcher of the
//! `modsecurity-operators` crate or one of the two operators that are part
//! of the engine itself, `@geoLookup` and `@inspectFile` (they need the
//! transaction).

pub mod geo_lookup;
pub mod inspect_file;
pub mod operator;
