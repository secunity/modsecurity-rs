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

use modsecurity_native::lmdb::{Code, Environment, MDB_NOTFOUND, Txn};

use crate::backend::collection_data::CollectionData;
use crate::{Collection, StorageError};
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
    fn txn_begin(&self, read_only: bool) -> Result<Txn<'static>, StorageError> {
        let environment = Environment::shared(SHARED_COLLECTIONS_PATH).ok_or(failed("open")(NO_ENVIRONMENT))?;
        environment.begin(read_only).map_err(failed("begin"))
    }

    /// Writes `key` with the value computed from its previous data (if any)
    /// in one write transaction: the shared body of `store_or_update_first`
    /// and `set_expiry`. A failure of LMDB leaves the key as it was.
    fn replace(&self, key: &[u8], build: impl FnOnce(CollectionData) -> CollectionData) -> Result<(), StorageError> {
        let mut txn = self.txn_begin(false)?;
        let mut previous_data = CollectionData::default();
        if let Some(previous) = found(txn.get(key).map(<[u8]>::to_vec))? {
            previous_data = CollectionData::from_bytes(&previous);
            // Deletes the pair just read.
            txn.del(key, &previous).map_err(failed("del"))?;
        }
        txn.put(key, &build(previous_data).serialize()).map_err(failed("put"))?;
        txn.commit().map_err(failed("commit"))
    }

    /// Deletes `key` if its value has expired. Cleaning up is best
    /// effort: an entry that could not be deleted is found expired again.
    fn del_if_expired(&self, key: &[u8]) {
        let _ = self.delete(key, true);
    }

    /// Deletes the first value of `key` (only when it has expired with
    /// `expired_only`), in its own write transaction. A key that is not
    /// there is not an error.
    fn delete(&self, key: &[u8], expired_only: bool) -> Result<(), StorageError> {
        let mut txn = self.txn_begin(false)?;
        let Some(value) = found(txn.get(key).map(<[u8]>::to_vec))? else {
            return Ok(());
        };
        if !expired_only || CollectionData::from_bytes(&value).is_expired() {
            // Deletes the pair just read.
            txn.del(key, &value).map_err(failed("del"))?;
        }
        txn.commit().map_err(failed("commit"))
    }

    /// Calls `f(key, data)` for the entries whose key `selected` accepts,
    /// among those that start with `prefix` (keys are sorted: the walk
    /// begins at the first of them and ends after the last). Entries that
    /// have expired are left out and deleted afterwards
    /// ([`Self::del_if_expired`]); so are entries without a value.
    fn walk(
        &self,
        prefix: &[u8],
        selected: impl Fn(&[u8]) -> bool,
        mut f: impl FnMut(&[u8], &[u8]),
    ) -> Result<(), StorageError> {
        let mut expired_vars: Vec<Vec<u8>> = Vec::new();

        let txn = self.txn_begin(true)?;
        let mut cursor = txn.cursor().map_err(failed("cursor"))?;
        let mut first = true;
        loop {
            let entry =
                if std::mem::take(&mut first) && !prefix.is_empty() { cursor.seek(prefix) } else { cursor.next() };
            // The end of the database (or an entry that cannot be read).
            let Ok((key, data)) = entry else { break };
            if !key.starts_with(prefix) {
                break;
            }
            if !selected(key) {
                continue;
            }
            let record = CollectionData::from_bytes(data);
            if record.is_expired() {
                expired_vars.push(key.to_vec());
            } else if let Some(value) = &record.value {
                f(key, value);
            }
        }
        drop(cursor);
        drop(txn); // mdb_txn_abort

        for expired_var in &expired_vars {
            self.del_if_expired(expired_var);
        }
        Ok(())
    }
}

/// An error of LMDB in `operation`.
fn failed(operation: &'static str) -> impl Fn(Code) -> StorageError {
    move |code| StorageError::new(operation, format!("code {code}"))
}

/// What a lookup found: a key that is not there is `None`, not an error.
fn found<T>(looked_up: Result<T, Code>) -> Result<Option<T>, StorageError> {
    match looked_up {
        Ok(value) => Ok(Some(value)),
        Err(MDB_NOTFOUND) => Ok(None),
        Err(code) => Err(failed("get")(code)),
    }
}

impl Collection for Lmdb {
    fn store_or_update_first(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        self.replace(key, |mut record| {
            record.set_value(value);
            record
        })
    }

    fn del(&self, key: &[u8]) -> Result<(), StorageError> {
        self.delete(key, false)
    }

    fn set_expiry(&self, key: &[u8], expiry_seconds: u64) -> Result<(), StorageError> {
        self.replace(key, |mut record| {
            record.set_expiry(expiry_seconds);
            record
        })
    }

    fn resolve_first(&self, var: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        let txn = self.txn_begin(true)?;
        let record = found(txn.get(var))?.map(CollectionData::from_bytes);
        drop(txn); // mdb_txn_abort

        // The read-only transaction is complete: an expired item can be
        // deleted now.
        match record {
            Some(record) if record.is_expired() => {
                self.del_if_expired(var);
                Ok(None)
            }
            Some(record) => Ok(record.value),
            None => Ok(None),
        }
    }

    fn resolve_multi_matches(
        &self,
        var: &[u8],
        l: &mut Vec<VariableValue>,
        ke: &KeyExclusions,
    ) -> Result<(), StorageError> {
        let name = self.name.as_bytes();
        let start = l.len();
        // Every key, or the key `var` alone.
        self.walk(
            var,
            |k| (var.is_empty() || k == var) && !ke.to_omit(k),
            |k, d| l.push(VariableValue::with_collection(name, k, d)),
        )?;
        move_to_front_reversed(l, start);
        Ok(())
    }

    fn resolve_regex(
        &self,
        prefix: &[u8],
        r: &Regex,
        l: &mut Vec<VariableValue>,
        ke: &KeyExclusions,
    ) -> Result<(), StorageError> {
        let name = self.name.as_bytes();
        let start = l.len();
        let selected = |k: &[u8]| r.is_match(&k[prefix.len()..]) && !ke.to_omit(k);
        self.walk(prefix, selected, |k, d| l.push(VariableValue::with_collection(name, k, d)))?;
        move_to_front_reversed(l, start);
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(in crate::backend) fn provider_in_temp_dir() {
        let dir = std::env::temp_dir().join(format!("msrs-lmdb-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = std::ffi::CString::new(dir.join("modsec-shared-collections").to_str().unwrap()).unwrap();
        // If another test already opened the default file, that one is
        // used; the keys below are unique to this test run.
        assert!(Environment::shared(&path).is_some());
    }

    /// A key that is not there is nothing found; any other code of LMDB
    /// is a failure, with the operation and the code.
    #[test]
    fn a_missing_key_is_not_a_failure() {
        assert_eq!(found(Ok(1)), Ok(Some(1)));
        assert_eq!(found::<u8>(Err(MDB_NOTFOUND)), Ok(None));
        let error = found::<u8>(Err(-30796)).unwrap_err();
        assert_eq!(error, StorageError::new("get", "code -30796"));
        assert_eq!(error.to_string(), "get failed (code -30796)");
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
        c.store_or_update_first(&k("a"), b"1").unwrap();
        assert_eq!(c.resolve_first(&k("a")).unwrap(), Some(b"1".to_vec()));
        c.store_or_update_first(&k("a"), b"2").unwrap();
        assert_eq!(c.resolve_first(&k("a")).unwrap(), Some(b"2".to_vec()));
        assert_eq!(c.resolve_first(&k("missing")).unwrap(), None);

        // expiry kept when the value is updated
        c.set_expiry(&k("a"), 100).unwrap();
        c.store_or_update_first(&k("a"), b"3").unwrap();
        assert_eq!(c.resolve_first(&k("a")).unwrap(), Some(b"3".to_vec()));

        // an expiry alone holds no value
        c.set_expiry(&k("noval"), 100).unwrap();
        assert_eq!(c.resolve_first(&k("noval")).unwrap(), None);

        // expired entries are not returned and get deleted
        c.store_or_update_first(&k("b"), b"old").unwrap();
        c.set_expiry(&k("b"), 0).unwrap();
        assert_eq!(c.resolve_first(&k("b")).unwrap(), None);

        // multi matches: the key alone, with the collection name
        c.store_or_update_first(&k("ab"), b"4").unwrap();
        let mut l = Vec::new();
        c.resolve_multi_matches(&k("a"), &mut l, &KeyExclusions::default()).unwrap();
        assert_eq!(keys(&l), vec![k("a")]);
        assert_eq!(l[0].key_with_collection(), [b"IP:".as_slice(), &k("a")].concat());
        assert_eq!(l[0].value(), b"3");

        let mut l = Vec::new();
        c.resolve_multi_matches(b"", &mut l, &KeyExclusions::default()).unwrap();
        assert!(keys(&l).contains(&k("ab")));

        // regular expression (case insensitive), in reverse key order
        let mut l = Vec::new();
        let prefix = format!("{p}::");
        c.resolve_regex(prefix.as_bytes(), &Regex::new_case("^A", true), &mut l, &KeyExclusions::default()).unwrap();
        assert_eq!(keys(&l), vec![k("ab"), k("a")]);
        assert_eq!(l[0].key_with_collection(), [b"IP:".as_slice(), &k("ab")].concat());

        // delete
        c.del(&k("a")).unwrap();
        assert_eq!(c.resolve_first(&k("a")).unwrap(), None);
        c.del(&k("ab")).unwrap();
        c.del(&k("noval")).unwrap();
    }
}
