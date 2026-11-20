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
/// did, and the code of the storage (an LMDB code).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageError {
    pub operation: &'static str,
    pub code: i32,
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} failed (code {})", self.operation, self.code)
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

    /// Parses the canonical uppercase names. Callers retain their own
    /// case rules (Lua normalizes; initcol/expirevar accept lowercase only).
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "GLOBAL" => Some(Self::Global),
            "IP" => Some(Self::Ip),
            "RESOURCE" => Some(Self::Resource),
            "SESSION" => Some(Self::Session),
            "USER" => Some(Self::User),
            _ => None,
        }
    }
}
