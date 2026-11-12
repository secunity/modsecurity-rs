//! Port of `src/collection/backend/in_memory-per_process.h` /
//! `src/collection/backend/in_memory-per_process.cc`.

use std::sync::RwLock;

use crate::collection::Collection;
use crate::collection::backend::collection_data::CollectionData;
use crate::utils::regex::Regex;
use crate::utils::unordered_multimap::UnorderedMultimap;
use crate::variable_value::{VariableValue, move_to_front_reversed};
use crate::variables::variable::KeyExclusions;

/// Process local collection: a case insensitive multimap guarded by a
/// reader/writer lock (the C++ code uses a `std::shared_mutex`).
pub struct InMemoryPerProcess {
    name: String,
    map: RwLock<UnorderedMultimap<CollectionData>>,
}

impl InMemoryPerProcess {
    pub fn new(name: &str) -> Self {
        InMemoryPerProcess { name: name.to_string(), map: RwLock::new(UnorderedMultimap::with_reserve(1000)) }
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, UnorderedMultimap<CollectionData>> {
        self.map.write().unwrap_or_else(|e| e.into_inner())
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, UnorderedMultimap<CollectionData>> {
        self.map.read().unwrap_or_else(|e| e.into_inner())
    }

    /// `store`
    pub fn store(&self, key: &[u8], value: &[u8]) {
        self.write().insert(key.to_vec(), CollectionData::with_value(value));
    }

    /// `delIfExpired`
    pub fn del_if_expired(&self, key: &[u8]) {
        let mut m = self.write();
        let found = m.iter().any(|(k, v)| k == key && v.is_expired());
        if found {
            m.erase(key);
        }
    }

    fn purge(&self, expired: Vec<Vec<u8>>) {
        for k in expired {
            self.del_if_expired(&k);
        }
    }
}

impl Collection for InMemoryPerProcess {
    fn name(&self) -> &str {
        &self.name
    }

    fn store_or_update_first(&self, key: &[u8], value: &[u8]) -> bool {
        let mut m = self.write();
        if let Some(d) = m.find_mut(key) {
            d.set_value(value);
        } else {
            m.insert(key.to_vec(), CollectionData::with_value(value));
        }
        true
    }

    fn update_first(&self, key: &[u8], value: &[u8]) -> bool {
        let mut m = self.write();
        if let Some(d) = m.find_mut(key) {
            d.set_value(value);
            return true;
        }
        false
    }

    fn del(&self, key: &[u8]) {
        self.write().erase(key);
    }

    fn set_expiry(&self, key: &[u8], expiry_seconds: i32) {
        let mut m = self.write();
        if let Some(d) = m.find_mut(key) {
            d.set_expiry(expiry_seconds);
            return;
        }
        // An expiry may be set for a key that has no value (yet).
        let mut d = CollectionData::default();
        d.set_expiry(expiry_seconds);
        m.insert(key.to_vec(), d);
    }

    fn resolve_first(&self, var: &[u8]) -> Option<Vec<u8>> {
        let mut ret = None;
        let mut expired = Vec::new();
        {
            let m = self.read();
            for (k, d) in m.equal_range(var) {
                if d.is_expired() {
                    expired.push(k.to_vec());
                } else if let Some(value) = &d.value {
                    ret = Some(value.clone());
                }
            }
        }
        self.purge(expired);
        ret
    }

    fn resolve_single_match(&self, var: &[u8], l: &mut Vec<VariableValue>) {
        let mut expired = Vec::new();
        {
            let m = self.read();
            for (k, d) in m.equal_range(var) {
                if d.is_expired() {
                    expired.push(k.to_vec());
                } else if let Some(value) = &d.value {
                    l.push(VariableValue::with_collection(self.name.as_bytes(), k, value));
                }
            }
        }
        self.purge(expired);
    }

    fn resolve_multi_matches(&self, var: &[u8], l: &mut Vec<VariableValue>, ke: &KeyExclusions) {
        let mut expired = Vec::new();
        let start = l.len();
        {
            let m = self.read();
            if var.is_empty() {
                for (k, d) in m.iter() {
                    if ke.to_omit(k) {
                        continue;
                    }
                    if d.is_expired() {
                        expired.push(k.to_vec());
                    } else if let Some(value) = &d.value {
                        l.push(VariableValue::with_collection(self.name.as_bytes(), k, value));
                    }
                }
            } else {
                for (k, d) in m.equal_range(var) {
                    if ke.to_omit(var) {
                        continue;
                    }
                    if d.is_expired() {
                        expired.push(k.to_vec());
                    } else if let Some(value) = &d.value {
                        l.push(VariableValue::with_collection(self.name.as_bytes(), var, value));
                    }
                }
            }
        }
        move_to_front_reversed(l, start);
        self.purge(expired);
    }

    fn resolve_regex(&self, r: &Regex, l: &mut Vec<VariableValue>, ke: &KeyExclusions) {
        let mut expired = Vec::new();
        let start = l.len();
        {
            let m = self.read();
            for (k, d) in m.iter() {
                if r.search(k) <= 0 {
                    continue;
                }
                if ke.to_omit(k) {
                    continue;
                }
                if d.is_expired() {
                    expired.push(k.to_vec());
                } else if let Some(value) = &d.value {
                    l.push(VariableValue::with_collection(self.name.as_bytes(), k, value));
                }
            }
        }
        move_to_front_reversed(l, start);
        self.purge(expired);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_only_and_empty_values_remain_distinct() {
        let collection = InMemoryPerProcess::new("TX");
        collection.set_expiry(b"key", 100);
        assert_eq!(collection.resolve_first(b"key"), None);
        collection.store_or_update_first(b"key", b"");
        assert_eq!(collection.resolve_first(b"key"), Some(Vec::new()));
        collection.set_expiry(b"key", 0);
        assert_eq!(collection.resolve_first(b"key"), None);
        assert!(!collection.update_first(b"key", b"gone"));
    }

    #[test]
    fn duplicate_resolution_and_expiry_keep_their_order() {
        let collection = InMemoryPerProcess::new("TX");
        collection.store(b"key", b"older");
        collection.store(b"key", b"newer");
        // resolve_first walks all equivalents, returning the last live one.
        assert_eq!(collection.resolve_first(b"key"), Some(b"older".to_vec()));
        let mut values = Vec::new();
        collection.resolve_single_match(b"key", &mut values);
        assert_eq!(values.iter().map(VariableValue::value).collect::<Vec<_>>(), [b"newer", b"older"]);
        values = vec![VariableValue::new(b"existing", b"value")];
        collection.resolve_multi_matches(b"key", &mut values, &KeyExclusions::default());
        assert_eq!(values.iter().map(VariableValue::value).collect::<Vec<_>>(), [b"older", b"newer", b"value"]);

        // Expiring the first equivalent removes the whole group, but the
        // current resolution still returns the other live value it visited.
        collection.set_expiry(b"key", 0);
        assert_eq!(collection.resolve_first(b"key"), Some(b"older".to_vec()));
        assert_eq!(collection.resolve_first(b"key"), None);
    }
}
