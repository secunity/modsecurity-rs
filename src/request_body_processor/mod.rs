//! The request body processors (the `modsecurity-body` crate); the
//! transaction is their context (`transaction/body.rs`). Their tests
//! through a transaction are here.

pub use modsecurity_body::{json, multipart, xml};

#[cfg(test)]
#[path = "tests/json.rs"]
mod json_tests;
#[cfg(test)]
#[path = "tests/multipart.rs"]
pub(crate) mod multipart_tests;
#[cfg(test)]
#[path = "tests/xml.rs"]
mod xml_tests;
