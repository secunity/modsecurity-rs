//! The in-memory collection backend, local to the process.
//!
//! An expired entry is invisible to readers. The reader that meets one
//! deletes its key; keys nobody reads again (a client seen once, under
//! `initcol:ip=%{REMOTE_ADDR}` with `expirevar`) are deleted by a sweep
//! of the whole map, which a write that adds an entry runs once the map
//! has grown to twice what the last sweep left (and at least
//! [`FIRST_SWEEP`] entries): its cost is spread over the writes that
//! filled the map, a constant per write.

use std::sync::RwLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::SystemTime;

use crate::backend::collection_data::CollectionData;
use crate::{Collection, StorageError};
use modsecurity_compat::unordered_multimap::UnorderedMultimap;
use modsecurity_native::regex::Regex;
use modsecurity_types::KeyExclusions;
use modsecurity_types::variable_value::{VariableValue, move_to_front_reversed};

/// The number of entries at which the first sweep runs.
const FIRST_SWEEP: usize = 1024;

/// Process local collection: a case insensitive multimap guarded by a
/// reader/writer lock.
pub struct InMemoryPerProcess {
    name: String,
    map: RwLock<UnorderedMultimap<CollectionData>>,
    /// The number of entries at which the next sweep runs (only changed
    /// under the write lock).
    next_sweep: AtomicUsize,
}

impl InMemoryPerProcess {
    pub fn new(name: &str) -> Self {
        InMemoryPerProcess {
            name: name.to_string(),
            map: RwLock::new(UnorderedMultimap::with_reserve(1000)),
            next_sweep: AtomicUsize::new(FIRST_SWEEP),
        }
    }

    /// Adds an entry, and sweeps the expired ones when it is time to.
    fn insert(&self, m: &mut UnorderedMultimap<CollectionData>, key: &[u8], data: CollectionData) {
        m.insert(key.to_vec(), data);
        if m.len() >= self.next_sweep.load(Ordering::Relaxed) {
            Self::sweep(m);
            self.next_sweep.store(FIRST_SWEEP.max(m.len().saturating_mul(2)), Ordering::Relaxed);
        }
    }

    /// Deletes the keys whose entries have all expired.
    fn sweep(m: &mut UnorderedMultimap<CollectionData>) {
        let now = SystemTime::now();
        let expired: Vec<Vec<u8>> =
            m.iter().filter(|(_, d)| d.is_expired_at(now)).map(|(key, _)| key.to_vec()).collect();
        for key in expired {
            if m.equal_range(&key).all(|(_, d)| d.is_expired_at(now)) {
                m.erase(&key);
            }
        }
    }

    #[cfg(test)]
    /// The number of entries stored, live or expired.
    fn len(&self) -> usize {
        self.read().len()
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
        self.insert(&mut self.write(), key, CollectionData::with_value(value));
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
            self.insert(&mut m, key, CollectionData::with_value(value));
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
        self.insert(&mut m, key, d);
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

    /// Keys that expire and are never read again are deleted by the writes
    /// that follow; live keys stay, and the sweeps keep the map within
    /// twice its live entries (or the first sweep's size).
    #[test]
    fn expired_keys_nobody_reads_are_swept() {
        let collection = InMemoryPerProcess::new("IP");
        let key = |n: usize| format!("client-{n}::timeout").into_bytes();
        for n in 0..10 * FIRST_SWEEP {
            collection.store_or_update_first(&key(n), b"1").unwrap();
            // Expired at once: a time that has passed when it is read.
            collection.set_expiry(&key(n), 0).unwrap();
            assert!(collection.len() <= FIRST_SWEEP, "{n}: {}", collection.len());
        }

        // With live keys among them: the live ones stay, the map stays
        // within twice what is live (plus one sweep's worth of writes).
        let live = |n: usize| format!("live-{n}").into_bytes();
        for n in 0..3 * FIRST_SWEEP {
            collection.store_or_update_first(&live(n), b"live").unwrap();
            collection.set_expiry(&live(n), 1000).unwrap();
            collection.store_or_update_first(&key(n), b"1").unwrap();
            collection.set_expiry(&key(n), 0).unwrap();
        }
        assert!(collection.len() <= 2 * 3 * FIRST_SWEEP, "{}", collection.len());
        for n in 0..3 * FIRST_SWEEP {
            assert_eq!(collection.resolve_first(&live(n)).unwrap(), Some(b"live".to_vec()));
            assert_eq!(collection.resolve_first(&key(n)).unwrap(), None);
        }
        // The reads deleted the expired keys the sweeps had not reached.
        assert_eq!(collection.len(), 3 * FIRST_SWEEP);
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
