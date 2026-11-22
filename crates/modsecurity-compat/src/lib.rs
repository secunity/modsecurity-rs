//! Data structures and parsers that reproduce the observable behavior of
//! the C++ libmodsecurity, quirks included. They are separate from the
//! engine because that is all they have in common: each one exists so that
//! results (match order, variable order, accepted input, messages) stay
//! what the C++ library gives, where a standard Rust equivalent would
//! differ.
//!
//! - [`unordered_multimap`]: a multimap that iterates in the order of
//!   libstdc++'s `std::unordered_multimap` (the order of `ARGS` & co.);
//! - [`json`]: a JSON reader and writer that accept and produce what yajl
//!   does;
//! - [`chars`]: the byte classes and string helpers the others share;
//! - [`cnum`]: the integer a text starts with, as C's `strtoll` and `atoll` read it.

#![forbid(unsafe_code)]

pub mod chars;
pub mod cnum;
pub mod errno;
pub mod json;
pub mod unordered_multimap;
