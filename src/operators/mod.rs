//! The operators: [`operator::Operator`] is a matcher of the
//! `modsecurity-operators` crate or `@inspectFile`, the one operator that
//! is part of the engine itself (it runs a Lua script or a program with
//! the transaction).

pub mod inspect_file;
pub mod operator;
