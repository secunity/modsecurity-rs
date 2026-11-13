//! Port of `headers/modsecurity/collection/collection.h`.
//!
//! Shared persistent key/value stores (`IP`, `SESSION`, ...). Persistent
//! collections are shared by every transaction (and thread) of a
//! `ModSecurity` instance, so the methods take `&self` and implementations
//! synchronise internally, as the C++ backends do.
//! Transaction-owned `TX` variables use [`transaction::TransactionVariables`]
//! instead: they need neither a storage backend nor shared mutation.

pub mod backend;
pub mod collections;
pub mod transaction;

use crate::utils::regex::Regex;
use crate::variable_value::VariableValue;
use crate::variables::variable::KeyExclusions;

/// Builds the compartmentalised key used by the C++ overloads that take one
/// or two compartments: `compartment::key` or
/// `compartment::compartment2::key`.
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

pub trait Collection: Send + Sync {
    /// `m_name`
    fn name(&self) -> &str;

    fn store_or_update_first(&self, key: &[u8], value: &[u8]) -> bool;

    fn update_first(&self, key: &[u8], value: &[u8]) -> bool;

    fn del(&self, key: &[u8]);

    fn set_expiry(&self, key: &[u8], expiry_seconds: i32);

    fn resolve_first(&self, var: &[u8]) -> Option<Vec<u8>>;

    fn resolve_single_match(&self, var: &[u8], l: &mut Vec<VariableValue>);

    fn resolve_multi_matches(&self, var: &[u8], l: &mut Vec<VariableValue>, ke: &KeyExclusions);

    /// The values whose key matches `r`.
    fn resolve_regex(&self, r: &Regex, l: &mut Vec<VariableValue>, ke: &KeyExclusions);

    /// `resolveRegularExpression`: [`Collection::resolve_regex`] with the
    /// pattern `var`, compiled as the C++ code does (case insensitive,
    /// multi-line).
    fn resolve_regular_expression(&self, var: &[u8], l: &mut Vec<VariableValue>, ke: &KeyExclusions) {
        self.resolve_regex(&Regex::with_options(var, true, true), l, ke)
    }
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
    #[cfg(feature = "lua")]
    pub(crate) fn from_name(name: &str) -> Option<Self> {
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
