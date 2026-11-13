//! Transaction-owned variables (`TX`).
//!
//! TX has no persistence or expiry actions. Mutation requires the owning
//! transaction; reads borrow bytes without locks or cleanup side effects.
//! The compatibility container and its initial reserve retain the observable
//! ordering used by macro expansion and rule targets.

use crate::utils::regex::Regex;
use crate::utils::unordered_multimap::UnorderedMultimap;
use crate::variable_value::{VariableValue, move_to_front_reversed};
use crate::variables::variable::KeyExclusions;

pub struct TransactionVariables {
    values: UnorderedMultimap<Vec<u8>>,
}

impl Default for TransactionVariables {
    fn default() -> Self {
        Self { values: UnorderedMultimap::with_reserve(1000) }
    }
}

impl TransactionVariables {
    pub fn get(&self, key: &[u8]) -> Option<&[u8]> {
        self.values.find(key).map(|(_, value)| value.as_slice())
    }

    /// Case-insensitive replacement retains the original key spelling and
    /// position. The value transfers into TX; there is only one per key.
    pub fn set(&mut self, key: &[u8], value: Vec<u8>) {
        if let Some(stored) = self.values.find_mut(key) {
            *stored = value;
        } else {
            self.values.insert(key.to_vec(), value);
        }
    }

    pub fn remove(&mut self, key: &[u8]) {
        self.values.erase(key);
    }

    pub(crate) fn resolve_multi_matches(&self, key: &[u8], out: &mut Vec<VariableValue>, exclusions: &KeyExclusions) {
        let start = out.len();
        if key.is_empty() {
            for (key, value) in self.values.iter() {
                if !exclusions.to_omit(key) {
                    out.push(VariableValue::with_collection(b"TX", key, value));
                }
            }
        } else if !exclusions.to_omit(key)
            && let Some(value) = self.get(key)
        {
            // A keyed resolution reports the requested spelling, whereas
            // whole-collection and regex resolutions use the stored spelling.
            out.push(VariableValue::with_collection(b"TX", key, value));
        }
        move_to_front_reversed(out, start);
    }

    pub(crate) fn resolve_regex(&self, regex: &Regex, out: &mut Vec<VariableValue>, exclusions: &KeyExclusions) {
        let start = out.len();
        for (key, value) in self.values.iter() {
            if regex.search(key) > 0 && !exclusions.to_omit(key) {
                out.push(VariableValue::with_collection(b"TX", key, value));
            }
        }
        move_to_front_reversed(out, start);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collection::Collection;
    use crate::collection::backend::in_memory_per_process::InMemoryPerProcess;
    use crate::variables::variable::KeyExclusion;

    #[test]
    fn empty_binary_and_case_insensitive_values() {
        let mut tx = TransactionVariables::default();
        assert_eq!(tx.get(b"name"), None);
        tx.set(b"Name", b"\xff\0value".to_vec());
        assert_eq!(tx.get(b"NAME"), Some(&b"\xff\0value"[..]));
        tx.set(b"name", Vec::new());
        assert_eq!(tx.get(b"NAME"), Some(&b""[..]));
        let mut out = Vec::new();
        tx.resolve_multi_matches(b"", &mut out, &KeyExclusions::default());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].key_with_collection(), b"TX:Name");
        tx.remove(b"nAmE");
        assert_eq!(tx.get(b"Name"), None);
        tx.set(b"", b"empty key".to_vec());
        assert_eq!(tx.get(b""), Some(&b"empty key"[..]));
    }

    #[test]
    fn resolution_matches_previous_backend_across_rehash_and_removal() {
        let mut tx = TransactionVariables::default();
        let previous = InMemoryPerProcess::new("TX");
        // Exceed the original reserve, include hash collisions, case aliases,
        // embedded NULs and non-ASCII keys, then delete and reinsert entries.
        let mut keys: Vec<Vec<u8>> = (0..1400).map(|i| format!("key-{i}").into_bytes()).collect();
        keys.extend([b"".to_vec(), b"ab".to_vec(), b"ba".to_vec(), b"\xff\0x".to_vec()]);
        for (i, key) in keys.iter().enumerate() {
            let value = i.to_string();
            tx.set(key, value.as_bytes().to_vec());
            previous.store_or_update_first(key, value.as_bytes());
        }
        for (i, key) in keys.iter().enumerate() {
            if i % 3 == 0 {
                tx.remove(key);
                previous.del(key);
            }
            let uppercase = key.to_ascii_uppercase();
            tx.set(&uppercase, b"updated".to_vec());
            previous.store_or_update_first(&uppercase, b"updated");
            assert_eq!(tx.get(key), previous.resolve_first(key).as_deref());
        }
        let exclusions = KeyExclusions(vec![KeyExclusion::string("KEY-1"), KeyExclusion::regex("^key-2")]);
        for exclusions in [&KeyExclusions::default(), &exclusions] {
            for key in [&b""[..], b"key-1", b"KEY-3", b"absent", b"\xff\0x"] {
                let mut actual = vec![VariableValue::new(b"existing", b"tail")];
                let mut expected = actual.clone();
                tx.resolve_multi_matches(key, &mut actual, exclusions);
                previous.resolve_multi_matches(key, &mut expected, exclusions);
                assert_eq!(actual, expected);
            }
            for pattern in [".", "^KEY-[123]", "absent"] {
                let regex = Regex::new_case(pattern, true);
                let mut actual = vec![VariableValue::new(b"existing", b"tail")];
                let mut expected = actual.clone();
                tx.resolve_regex(&regex, &mut actual, exclusions);
                previous.resolve_regex(&regex, &mut expected, exclusions);
                assert_eq!(actual, expected);
            }
        }
    }
}
