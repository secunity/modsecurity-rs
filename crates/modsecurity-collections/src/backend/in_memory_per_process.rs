//! The in-memory collection backend, local to the process.

use std::sync::RwLock;

use crate::backend::collection_data::CollectionData;
use crate::{Collection, StorageError};
use modsecurity_compat::unordered_multimap::UnorderedMultimap;
use modsecurity_native::regex::Regex;
use modsecurity_types::KeyExclusions;
use modsecurity_types::variable_value::{VariableValue, move_to_front_reversed};

/// Process local collection: a case insensitive multimap guarded by a
/// reader/writer lock.
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

    #[cfg(test)]
    /// Adds a value under `key` (keeping any existing ones).
    pub fn store(&self, key: &[u8], value: &[u8]) {
        self.write().insert(key.to_vec(), CollectionData::with_value(value));
    }

    /// Deletes the keys of `expired` that still have an expired entry (a
    /// key may have been written again since it was seen), under one lock.
    fn purge(&self, expired: Vec<Vec<u8>>) {
        if expired.is_empty() {
            return;
        }
        let mut m = self.write();
        for key in expired {
            if m.equal_range(&key).any(|(_, v)| v.is_expired()) {
                m.erase(&key);
            }
        }
    }
}

impl Collection for InMemoryPerProcess {
    fn store_or_update_first(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        let mut m = self.write();
        if let Some(d) = m.find_mut(key) {
            d.set_value(value);
        } else {
            m.insert(key.to_vec(), CollectionData::with_value(value));
        }
        Ok(())
    }

    fn del(&self, key: &[u8]) -> Result<(), StorageError> {
        self.write().erase(key);
        Ok(())
    }

    fn set_expiry(&self, key: &[u8], expiry_seconds: u64) -> Result<(), StorageError> {
        let mut m = self.write();
        if let Some(d) = m.find_mut(key) {
            d.set_expiry(expiry_seconds);
            return Ok(());
        }
        // An expiry may be set for a key that has no value (yet).
        let mut d = CollectionData::default();
        d.set_expiry(expiry_seconds);
        m.insert(key.to_vec(), d);
        Ok(())
    }

    fn resolve_first(&self, var: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
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
        Ok(ret)
    }

    fn resolve_multi_matches(
        &self,
        var: &[u8],
        l: &mut Vec<VariableValue>,
        ke: &KeyExclusions,
    ) -> Result<(), StorageError> {
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
        Ok(())
    }

    fn resolve_regex(
        &self,
        prefix: &[u8],
        r: &Regex,
        l: &mut Vec<VariableValue>,
        ke: &KeyExclusions,
    ) -> Result<(), StorageError> {
        let mut expired = Vec::new();
        let start = l.len();
        {
            let m = self.read();
            for (k, d) in m.iter() {
                // Keys ignore case, so the compartment does too.
                let named = k.split_at_checked(prefix.len()).filter(|(p, _)| p.eq_ignore_ascii_case(prefix));
                if !named.is_some_and(|(_, name)| r.is_match(name)) {
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
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_only_and_empty_values_remain_distinct() {
        let collection = InMemoryPerProcess::new("TX");
        collection.set_expiry(b"key", 100).unwrap();
        assert_eq!(collection.resolve_first(b"key").unwrap(), None);
        collection.store_or_update_first(b"key", b"").unwrap();
        assert_eq!(collection.resolve_first(b"key").unwrap(), Some(Vec::new()));
        collection.set_expiry(b"key", 0).unwrap();
        assert_eq!(collection.resolve_first(b"key").unwrap(), None);
    }

    #[test]
    fn duplicate_resolution_and_expiry_keep_their_order() {
        let collection = InMemoryPerProcess::new("TX");
        collection.store(b"key", b"older");
        collection.store(b"key", b"newer");
        // resolve_first walks all equivalents, returning the last live one.
        assert_eq!(collection.resolve_first(b"key").unwrap(), Some(b"older".to_vec()));
        let mut values = vec![VariableValue::new(b"existing", b"value")];
        collection.resolve_multi_matches(b"key", &mut values, &KeyExclusions::default()).unwrap();
        assert_eq!(values.iter().map(VariableValue::value).collect::<Vec<_>>(), [b"older", b"newer", b"value"]);

        // Expiring the first equivalent removes the whole group, but the
        // current resolution still returns the other live value it visited.
        collection.set_expiry(b"key", 0).unwrap();
        assert_eq!(collection.resolve_first(b"key").unwrap(), Some(b"older".to_vec()));
        assert_eq!(collection.resolve_first(b"key").unwrap(), None);
    }
}
