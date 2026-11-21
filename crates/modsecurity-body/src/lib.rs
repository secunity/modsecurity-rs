//! The request body processors of ModSecurity: [`multipart`]
//! (`multipart/form-data`), [`json`] and [`xml`].
//!
//! Each one parses a body and reports what it finds, the arguments and
//! (for multipart) the many `MULTIPART_*` and `FILES*` variables, through
//! a context trait its caller implements; the ModSecurity engine
//! implements them for its transaction. Nothing here knows about rules.

#![forbid(unsafe_code)]

pub mod json;
pub mod multipart;
mod names;
pub mod xml;
