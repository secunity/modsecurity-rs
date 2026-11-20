//! The LMDB collection backend.
//!
//! Persistent collections (`IP`, `SESSION`, `USER`, `GLOBAL`, `RESOURCE`)
//! stored in an LMDB file shared by every process using the library:
//! `./modsec-shared-collections` (relative to the working directory).
//! Values are stored as `CollectionData::serialize` (value + expiry).
//!
//! The LMDB calls go through `modsecurity_native::lmdb`; the environment
//! and its database live for the whole process.
#![cfg(feature = "lmdb")]

use std::ffi::CStr;

use modsecurity_native::lmdb::{Code, Environment, Txn};

use crate::Collection;
use crate::backend::collection_data::CollectionData;
use modsecurity_native::regex::Regex;
use modsecurity_types::KeyExclusions;
use modsecurity_types::variable_value::{VariableValue, move_to_front_reversed};

/// The location of the shared collections file.
const SHARED_COLLECTIONS_PATH: &CStr = c"./modsec-shared-collections";

/// The code of a failure to open the environment.
const NO_ENVIRONMENT: Code = -1;

/// A collection stored in the shared LMDB database (`WITH_LMDB`).
pub struct Lmdb {
    name: String,
}

impl Lmdb {
    pub fn new(name: &str) -> Self {
        Lmdb { name: name.to_string() }
    }

    /// Begins an LMDB transaction, opening the shared environment on first
    /// use; [`NO_ENVIRONMENT`] when it could not be opened.
    fn txn_begin(&self, read_only: bool) -> Result<Txn<'static>, Code> {
        Environment::shared(SHARED_COLLECTIONS_PATH).ok_or(NO_ENVIRONMENT)?.begin(read_only)
    }

    /// Writes `key` with the value computed from its previous data (if any)
    /// in one write transaction: the shared body of `store_or_update_first`
    /// and `set_expiry`. A failure of LMDB leaves the key as it was.
    fn replace(&self, key: &[u8], build: impl FnOnce(CollectionData) -> CollectionData) -> Result<(), Code> {
        let mut txn = self.txn_begin(false)?;
        let mut previous_data = CollectionData::default();
        if let Ok(previous) = txn.get(key).map(<[u8]>::to_vec) {
            previous_data = CollectionData::from_bytes(&previous);
            // Deletes the pair just read.
            txn.del(key, &previous)?;
        }
        txn.put(key, &build(previous_data).serialize())?;
        txn.commit()
    }

    /// Deletes `key` if its value has expired.
    fn del_if_expired(&self, key: &[u8]) {
        let _ = self.delete(key, true);
    }

    /// Deletes the first value of `key` (only when it has expired with
    /// `expired_only`), in its own write transaction.
    fn delete(&self, key: &[u8], expired_only: bool) -> Result<(), Code> {
        let mut txn = self.txn_begin(false)?;
        let value = txn.get(key)?.to_vec();
        if !expired_only || CollectionData::from_bytes(&value).is_expired() {
            // Deletes the pair just read.
            txn.del(key, &value)?;
        }
        txn.commit()
    }

    /// Walks the database with a cursor in a read-only transaction, calling
    /// `f(key, data)` for every non expired entry holding a value; the
    /// expired entries are deleted afterwards ([`Self::del_if_expired`]).
    ///
    /// The walk starts at the first database entry.
    fn walk(&self, mut f: impl FnMut(&[u8], &[u8])) {
        let mut expired_vars: Vec<Vec<u8>> = Vec::new();

        if let Ok(txn) = self.txn_begin(true) {
            if let Ok(mut cursor) = txn.cursor() {
                while let Ok((key, data)) = cursor.next() {
                    let record = CollectionData::from_bytes(data);
                    if record.is_expired() {
                        expired_vars.push(key.to_vec());
                    } else if let Some(value) = &record.value {
                        f(key, value);
                    }
                }
            }
            drop(txn); // mdb_txn_abort
        }

        for expired_var in &expired_vars {
            self.del_if_expired(expired_var);
        }
    }
}

impl Collection for Lmdb {
    fn store_or_update_first(&self, key: &[u8], value: &[u8]) -> bool {
        let _ = self.replace(key, |mut record| {
            record.set_value(value);
            record
        });
        true
    }

    fn del(&self, key: &[u8]) {
        let _ = self.delete(key, false);
    }

    fn set_expiry(&self, key: &[u8], expiry_seconds: i32) {
        let _ = self.replace(key, |mut record| {
            record.set_expiry(expiry_seconds);
            record
        });
    }

    fn resolve_first(&self, var: &[u8]) -> Option<Vec<u8>> {
        let mut ret = None;
        let mut collection_data = CollectionData::default();

        if let Ok(txn) = self.txn_begin(true) {
            if let Ok(value) = txn.get(var) {
                collection_data = CollectionData::from_bytes(value);
                if !collection_data.is_expired() {
                    ret = collection_data.value.take();
                }
            }
            drop(txn); // mdb_txn_abort
        }

        // The read-only transaction is complete. Now we can do a delete if
        // the item was expired.
        if collection_data.is_expired() {
            self.del_if_expired(var);
        }
        ret
    }

    /// Quirk (C++): the key exclusions are not applied, and a non empty
    /// `var` selects every key it prefixes.
    fn resolve_multi_matches(&self, var: &[u8], l: &mut Vec<VariableValue>, _ke: &KeyExclusions) {
        let name = self.name.as_bytes();
        let start = l.len();
        if var.is_empty() {
            self.walk(|k, d| {
                l.push(VariableValue::with_collection(name, k, d));
            });
        } else {
            self.walk(|k, d| {
                if k.starts_with(var) {
                    l.push(VariableValue::with_collection(name, k, d));
                }
            });
        }
        move_to_front_reversed(l, start);
    }

    fn resolve_regex(&self, prefix: &[u8], r: &Regex, l: &mut Vec<VariableValue>, ke: &KeyExclusions) {
        let start = l.len();
        self.walk(|k, d| {
            if !k.strip_prefix(prefix).is_some_and(|name| r.is_match(name)) {
                return;
            }
            if ke.to_omit(k) {
                return;
            }
            l.push(VariableValue::new(k, d));
        });
        move_to_front_reversed(l, start);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider_in_temp_dir() {
        let dir = std::env::temp_dir().join(format!("msrs-lmdb-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = std::ffi::CString::new(dir.join("modsec-shared-collections").to_str().unwrap()).unwrap();
        // If another test already opened the default file, that one is
        // used; the keys below are unique to this test run.
        assert!(Environment::shared(&path).is_some());
    }

    fn keys(l: &[VariableValue]) -> Vec<Vec<u8>> {
        l.iter().map(|v| v.key().to_vec()).collect()
    }

    #[test]
    fn store_resolve_expiry_regex() {
        provider_in_temp_dir();
        let p = format!(
            "t{}_{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
        );
        let k = |s: &str| format!("{}::{}", p, s).into_bytes();
        let c = Lmdb::new("IP");

        // store / update / resolve
        assert!(c.store_or_update_first(&k("a"), b"1"));
        assert_eq!(c.resolve_first(&k("a")), Some(b"1".to_vec()));
        assert!(c.store_or_update_first(&k("a"), b"2"));
        assert_eq!(c.resolve_first(&k("a")), Some(b"2".to_vec()));
        assert_eq!(c.resolve_first(&k("missing")), None);

        // expiry kept when the value is updated
        c.set_expiry(&k("a"), 100);
        assert!(c.store_or_update_first(&k("a"), b"3"));
        assert_eq!(c.resolve_first(&k("a")), Some(b"3".to_vec()));

        // an expiry alone holds no value
        c.set_expiry(&k("noval"), 100);
        assert_eq!(c.resolve_first(&k("noval")), None);

        // expired entries are not returned and get deleted
        assert!(c.store_or_update_first(&k("b"), b"old"));
        c.set_expiry(&k("b"), 0);
        assert_eq!(c.resolve_first(&k("b")), None);

        // multi matches: prefix selection, collection name, reverse order
        assert!(c.store_or_update_first(&k("ab"), b"4"));
        let mut l = Vec::new();
        c.resolve_multi_matches(&k("a"), &mut l, &KeyExclusions::default());
        assert_eq!(keys(&l), vec![k("ab"), k("a")]);
        assert_eq!(l[1].key_with_collection(), [b"IP:".as_slice(), &k("a")].concat());
        assert_eq!(l[1].value(), b"3");

        let mut l = Vec::new();
        c.resolve_multi_matches(b"", &mut l, &KeyExclusions::default());
        assert!(keys(&l).contains(&k("ab")));

        // regular expression (case insensitive), no collection prefix
        let mut l = Vec::new();
        let prefix = format!("{p}::");
        c.resolve_regex(prefix.as_bytes(), &Regex::new_case("^A", true), &mut l, &KeyExclusions::default());
        assert_eq!(keys(&l), vec![k("ab"), k("a")]);
        assert_eq!(l[0].key_with_collection(), k("ab").as_slice());

        // delete
        c.del(&k("a"));
        assert_eq!(c.resolve_first(&k("a")), None);
        c.del(&k("ab"));
        c.del(&k("noval"));
    }
}
