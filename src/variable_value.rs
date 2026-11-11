//! Port of `headers/modsecurity/variable_value.h`.
//!
//! Keys and values are byte strings: they come straight from the HTTP
//! request.

use crate::variable_origin::VariableOrigin;

/// Inserts `items` at the front of `l` one after the other, in order, as the
/// C++ code does with `l->insert(l->begin(), ...)` in a loop: the result is
/// `items` reversed, followed by the previous contents of `l`.
///
/// The C++ vector holds pointers, so its repeated front insertion is cheap
/// per element; with owned values it must be done in one splice to stay
/// linear (resolving `ARGS` with hundreds of arguments for every rule
/// otherwise dominates the evaluation time).
pub fn prepend_each(l: &mut Vec<VariableValue>, items: Vec<VariableValue>) {
    if items.is_empty() {
        return;
    }
    l.splice(0..0, items.into_iter().rev());
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepend_each_matches_repeated_front_insertion() {
        let v = |s: &str| VariableValue::new(s.as_bytes(), b"");
        let existing = vec![v("x"), v("y")];
        let items = vec![v("a"), v("b"), v("c")];

        let mut expected = existing.clone();
        for it in items.clone() {
            expected.insert(0, it);
        }
        let mut got = existing;
        prepend_each(&mut got, items);
        assert_eq!(got, expected);
        let keys: Vec<&[u8]> = got.iter().map(|x| x.key()).collect();
        assert_eq!(keys, [b"c".as_slice(), b"b", b"a", b"x", b"y"]);
    }
}
