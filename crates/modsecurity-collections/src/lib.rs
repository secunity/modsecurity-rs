//! The [`Collection`] interface of the persistent collection backends.
//!
//! Shared persistent key/value stores (`IP`, `SESSION`, ...). Persistent
//! collections are shared by every transaction (and thread) of a
//! `ModSecurity` instance, so the methods take `&self` and implementations
//! synchronise internally.
//! Transaction-owned `TX` variables use [`transaction::TransactionVariables`]
//! instead: they need neither a storage backend nor shared mutation.

// LMDB is called through the `modsecurity-native` crate.
#![forbid(unsafe_code)]

pub mod backend;
pub mod collections;
pub mod transaction;

use modsecurity_native::regex::Regex;
use modsecurity_types::KeyExclusions;
use modsecurity_types::variable_value::VariableValue;

/// Builds the key of a value stored in one or two compartments:
/// `compartment::key` or `compartment::compartment2::key`.
pub fn compartment_key(key: &[u8], compartment: &[u8], compartment2: Option<&[u8]>) -> Vec<u8> {
    let mut nkey = compartment.to_vec();
    nkey.extend_from_slice(b"::");
    if let Some(c2) = compartment2 {
        nkey.extend_from_slice(c2);
        nkey.extend_from_slice(b"::");
    }
    nkey.extend_from_slice(key);
    nkey
}

/// The storage behind a persistent collection failed: the operation that
/// did, and what the storage said (for LMDB, `code N`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageError {
    pub operation: &'static str,
    pub cause: String,
}

impl StorageError {
    pub fn new(operation: &'static str, cause: impl Into<String>) -> Self {
        StorageError { operation, cause: cause.into() }
    }
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} failed ({})", self.operation, self.cause)
    }
}

impl std::error::Error for StorageError {}

/// The storage of a persistent collection. A key that is not there is not
/// an error; a storage that cannot be read or written is.
pub trait Collection: Send + Sync {
    /// Sets the value of `key`, keeping its expiry.
    fn store_or_update_first(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError>;

    fn del(&self, key: &[u8]) -> Result<(), StorageError>;

    fn set_expiry(&self, key: &[u8], expiry_seconds: u64) -> Result<(), StorageError>;

    fn resolve_first(&self, var: &[u8]) -> Result<Option<Vec<u8>>, StorageError>;

    fn resolve_multi_matches(
        &self,
        var: &[u8],
        l: &mut Vec<VariableValue>,
        ke: &KeyExclusions,
    ) -> Result<(), StorageError>;

    /// The values whose key is `prefix` (a compartment, see
    /// [`compartment_key`]) followed by a name that matches `r`.
    fn resolve_regex(
        &self,
        prefix: &[u8],
        r: &Regex,
        l: &mut Vec<VariableValue>,
        ke: &KeyExclusions,
    ) -> Result<(), StorageError>;
}

/// One of the persistent collections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Persistent {
    Global,
    Ip,
    Resource,
    Session,
    User,
}

impl Persistent {
    /// The collection name (`IP`, ...).
    pub fn name(self) -> &'static str {
        match self {
            Persistent::Global => "GLOBAL",
            Persistent::Ip => "IP",
            Persistent::Resource => "RESOURCE",
            Persistent::Session => "SESSION",
            Persistent::User => "USER",
        }
    }

    /// The collection named `name`, ignoring case (`ip`, `IP`, `Ip`, ...).
    /// Every place that names a collection (targets, `setvar`, `initcol`,
    /// `expirevar`, Lua's `m.setvar`) reads it with this.
    pub fn parse(name: &[u8]) -> Option<Self> {
        const ALL: [Persistent; 5] =
            [Persistent::Global, Persistent::Ip, Persistent::Resource, Persistent::Session, Persistent::User];
        ALL.into_iter().find(|c| name.eq_ignore_ascii_case(c.name().as_bytes()))
    }
}

#[cfg(test)]
mod persistent_tests {
    use super::Persistent;

    #[test]
    fn names_are_read_ignoring_case() {
        for name in ["ip", "IP", "Ip", "iP"] {
            assert_eq!(Persistent::parse(name.as_bytes()), Some(Persistent::Ip), "{name}");
        }
        assert_eq!(Persistent::parse(b"resource"), Some(Persistent::Resource));
        assert_eq!(Persistent::parse(b"Session"), Some(Persistent::Session));
        for name in ["tx", "ips", "", "i"] {
            assert_eq!(Persistent::parse(name.as_bytes()), None, "{name}");
        }
    }
}
