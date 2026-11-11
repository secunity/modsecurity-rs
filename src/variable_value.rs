//! Port of `headers/modsecurity/variable_value.h`.
//!
//! Keys and values are byte strings: they come straight from the HTTP
//! request.

use crate::variable_origin::VariableOrigin;

pub type Origins = Vec<VariableOrigin>;

/// A resolved variable: collection name, key and value, plus where the value
/// came from. In C++ resolution produced heap allocated copies owned by the
/// caller; here resolution produces owned values in a `Vec`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VariableValue {
    origin: Origins,
    collection: Vec<u8>,
    key: Vec<u8>,
    key_with_collection: Vec<u8>,
    value: Vec<u8>,
}

impl VariableValue {
    /// `VariableValue(const std::string *key, const std::string *value)`
    pub fn new(key: &[u8], value: &[u8]) -> Self {
        VariableValue {
            origin: Vec::new(),
            collection: Vec::new(),
            key: key.to_vec(),
            key_with_collection: key.to_vec(),
            value: value.to_vec(),
        }
    }

    /// `VariableValue(collection, key, value)`
    pub fn with_collection(collection: &[u8], key: &[u8], value: &[u8]) -> Self {
        let mut kwc = Vec::with_capacity(collection.len() + 1 + key.len());
        kwc.extend_from_slice(collection);
        kwc.push(b':');
        kwc.extend_from_slice(key);
        VariableValue {
            origin: Vec::new(),
            collection: collection.to_vec(),
            key: key.to_vec(),
            key_with_collection: kwc,
            value: value.to_vec(),
        }
    }

    pub fn key(&self) -> &[u8] {
        &self.key
    }

    pub fn key_with_collection(&self) -> &[u8] {
        &self.key_with_collection
    }

    pub fn collection(&self) -> &[u8] {
        &self.collection
    }

    pub fn value(&self) -> &[u8] {
        &self.value
    }

    pub fn set_value(&mut self, value: &[u8]) {
        self.value = value.to_vec();
    }

    pub fn add_origin(&mut self, origin: VariableOrigin) {
        self.origin.push(origin);
    }

    pub fn origin(&self) -> &Origins {
        &self.origin
    }

    pub fn reserve_origin(&mut self, additional: usize) {
        self.origin.reserve(additional);
    }
}
