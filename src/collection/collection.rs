//! Port of `headers/modsecurity/collection/collection.h`.
//!
//! A named key/value store backing `TX`, `IP`, `SESSION`, ... Persistent
//! collections are shared by every transaction (and thread) of a
//! `ModSecurity` instance, so the methods take `&self` and implementations
//! synchronise internally, as the C++ backends do.

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

    fn resolve_regular_expression(&self, var: &[u8], l: &mut Vec<VariableValue>, ke: &KeyExclusions);

    // The C++ compartment overloads, expressed with an optional second
    // compartment.

    fn store_or_update_first_c(&self, key: &[u8], c1: &[u8], c2: Option<&[u8]>, value: &[u8]) -> bool {
        self.store_or_update_first(&compartment_key(key, c1, c2), value)
    }

    fn update_first_c(&self, key: &[u8], c1: &[u8], c2: Option<&[u8]>, value: &[u8]) -> bool {
        self.update_first(&compartment_key(key, c1, c2), value)
    }

    fn del_c(&self, key: &[u8], c1: &[u8], c2: Option<&[u8]>) {
        self.del(&compartment_key(key, c1, c2))
    }

    fn set_expiry_c(&self, key: &[u8], c1: &[u8], c2: Option<&[u8]>, expiry_seconds: i32) {
        self.set_expiry(&compartment_key(key, c1, c2), expiry_seconds)
    }

    fn resolve_first_c(&self, var: &[u8], c1: &[u8], c2: Option<&[u8]>) -> Option<Vec<u8>> {
        self.resolve_first(&compartment_key(var, c1, c2))
    }

    fn resolve_single_match_c(&self, var: &[u8], c1: &[u8], c2: Option<&[u8]>, l: &mut Vec<VariableValue>) {
        self.resolve_single_match(&compartment_key(var, c1, c2), l)
    }

    fn resolve_multi_matches_c(
        &self,
        var: &[u8],
        c1: &[u8],
        c2: Option<&[u8]>,
        l: &mut Vec<VariableValue>,
        ke: &KeyExclusions,
    ) {
        self.resolve_multi_matches(&compartment_key(var, c1, c2), l, ke)
    }

    fn resolve_regular_expression_c(
        &self,
        var: &[u8],
        c1: &[u8],
        c2: Option<&[u8]>,
        l: &mut Vec<VariableValue>,
        ke: &KeyExclusions,
    ) {
        self.resolve_regular_expression(&compartment_key(var, c1, c2), l, ke)
    }
}
