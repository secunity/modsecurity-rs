//! The operators: the engine's [`operator::Operator`] trait, behind which
//! the matchers of the `modsecurity-operators` crate run, and the operators
//! that are part of the engine itself (they need the transaction).

pub mod geo_lookup;
pub mod inspect_file;
pub mod operator;
pub mod rbl;
pub mod validate_dtd;
pub mod validate_schema;
