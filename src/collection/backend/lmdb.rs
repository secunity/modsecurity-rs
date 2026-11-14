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
use std::os::raw::c_int;

use modsecurity_native::lmdb::{self, Code, Environment, Txn};

use crate::collection::Collection;
use crate::collection::backend::collection_data::CollectionData;
use crate::utils::regex::Regex;
use crate::variable_value::{VariableValue, move_to_front_reversed};
use crate::variables::variable::KeyExclusions;

/// Whether LMDB failures are printed on stdout: no, as in the C++ build
/// (where `LMDB_STDOUT_COUT` is undefined).
const LMDB_STDOUT_COUT: bool = false;

/// The location of the shared collections file.
const SHARED_COLLECTIONS_PATH: &CStr = c"./modsec-shared-collections";

/// The code of a failure to open the environment.
const NO_ENVIRONMENT: Code = -1;

/// Whether `key` starts with `var` (up to a NUL byte in `var`), as the C++
/// `strncmp(var.c_str(), key, var.size()) == 0`.
///
/// Deviation: the C++ code reads past the end of a key shorter than `var`
/// (into the LMDB page); such keys never match here.
fn key_matches_prefix(var: &[u8], key: &[u8]) -> bool {
    for (i, &c) in var.iter().enumerate() {
        match key.get(i) {
            Some(&k) if k == c => {
                if c == 0 {
                    return true;
                }
            }
            _ => return false,
        }
    }
    true
}

/// Describes an LMDB failure on stdout (compiled out, as in C++, unless
/// `LMDB_STDOUT_COUT` is set).
fn lmdb_debug(rc: c_int, op: &str, scope: &str) {
    if !LMDB_STDOUT_COUT || rc == 0 {
        return;
    }

    let msg = match op {
        "txn" => {
            let detail = match rc {
                lmdb::MDB_PANIC => {
                    "panic: a fatal error occurred earlier and the environment must be shut down.".to_string()
                }
                lmdb::MDB_MAP_RESIZED => {
                    "map resized: another process wrote data beyond this MDB_env's mapsize and this \
                                         environment's map must be resized as well. See mdb_env_set_mapsize()."
                        .to_string()
                }
                lmdb::MDB_READERS_FULL => "max readers: a read-only transaction was requested and the reader lock \
                                          table is full. See mdb_env_set_maxreaders()."
                    .to_string(),
                libc::ENOMEM => "out of memory.".to_string(),
                _ => format!("not sure what is wrong, code: {}", rc),
            };
            format!("{}, LMDB failure while starting txn: {}", scope, detail)
        }
        "get" => {
            let detail = match rc {
                lmdb::MDB_NOTFOUND => "not found: the key was not in the database.",
                libc::EINVAL => "an invalid parameter was specified.",
                _ => "not sure what is wrong.",
            };
            format!("{}, LMDB failure while getting the key: {}", scope, detail)
        }
        "del" => {
            let detail = match rc {
                libc::EACCES => "an attempt was made to write in a read-only transaction.".to_string(),
                libc::EINVAL => "an invalid parameter was specified.".to_string(),
                _ => format!("not sure what is wrong. Code: {}", rc),
            };
            format!("{}, delete procedure failed: {}", scope, detail)
        }
        "commit" => {
            let detail = match rc {
                libc::EINVAL => "an invalid parameter was specified.".to_string(),
                libc::ENOSPC => "no more disk space.".to_string(),
                libc::EIO => "a low-level I/O error occurred while writing.".to_string(),
                libc::ENOMEM => "out of memory.".to_string(),
                _ => format!("not sure what is wrong. Code: {}", rc),
            };
            format!("{}, commit procedure failed: {}", scope, detail)
        }
        _ => return,
    };
    println!("{}", msg);
}

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
    /// and `set_expiry`. Returns the last LMDB code (0 on success).
    fn replace(&self, key: &[u8], scope: &str, build: impl FnOnce(CollectionData) -> CollectionData) -> c_int {
        let mut txn = match self.txn_begin(false) {
            Ok(t) => t,
            Err(rc) => {
                lmdb_debug(rc, "txn", scope);
                return rc;
            }
        };

        let mut previous_data = CollectionData::default();
        let previous = txn.get(key).map(<[u8]>::to_vec);
        lmdb_debug(previous.as_ref().err().copied().unwrap_or(0), "get", scope);
        if let Ok(previous) = previous {
            previous_data = CollectionData::from_bytes(&previous);
            // Deletes the pair just read.
            if let Err(rc) = txn.del(key, &previous) {
                lmdb_debug(rc, "del", scope);
                return rc;
            }
        }

        let new_data = build(previous_data);
        if let Err(rc) = txn.put(key, &new_data.serialize()) {
            lmdb_debug(rc, "put", scope);
            return rc;
        }

        let rc = txn.commit().err().unwrap_or(0);
        lmdb_debug(rc, "commit", scope);
        rc
    }

    /// Deletes `key` if its value has expired.
    fn del_if_expired(&self, key: &[u8]) {
        self.delete(key, true);
    }

    /// Deletes the first value of `key` (only when it has expired with
    /// `expired_only`), in its own write transaction.
    fn delete(&self, key: &[u8], expired_only: bool) {
        let mut txn = match self.txn_begin(false) {
            Ok(t) => t,
            Err(rc) => {
                lmdb_debug(rc, "txn", "del");
                return;
            }
        };

        let value = match txn.get(key) {
            Ok(v) => v.to_vec(),
            Err(rc) => {
                lmdb_debug(rc, "get", "del");
                return;
            }
        };

        if !expired_only || CollectionData::from_bytes(&value).is_expired() {
            // Deletes the pair just read.
            if let Err(rc) = txn.del(key, &value) {
                lmdb_debug(rc, "del", "del");
                return;
            }
        }

        let rc = txn.commit().err().unwrap_or(0);
        lmdb_debug(rc, "commit", "del");
    }

    /// Walks the database with a cursor in a read-only transaction, calling
    /// `f(key, data)` for every non expired entry holding a value; the
    /// expired entries are deleted afterwards ([`Self::del_if_expired`]).
    ///
    /// The walk starts at the first database entry.
    fn walk(&self, scope: &str, mut f: impl FnMut(&[u8], &[u8])) {
        let mut expired_vars: Vec<Vec<u8>> = Vec::new();

        match self.txn_begin(true) {
            Err(rc) => lmdb_debug(rc, "txn", scope),
            Ok(txn) => {
                match txn.cursor() {
                    Err(rc) => lmdb_debug(rc, "cursor_open", scope),
                    Ok(mut cursor) => {
                        while let Ok((key, data)) = cursor.next() {
                            let record = CollectionData::from_bytes(data);
                            if record.is_expired() {
                                expired_vars.push(key.to_vec());
                            } else if let Some(value) = &record.value {
                                f(key, value);
                            }
                        }
                    }
                }
                drop(txn); // mdb_txn_abort
            }
        }

        for expired_var in &expired_vars {
            self.del_if_expired(expired_var);
        }
    }
}

impl Collection for Lmdb {
    fn store_or_update_first(&self, key: &[u8], value: &[u8]) -> bool {
        self.replace(key, "storeOrUpdateFirst", |mut record| {
            record.set_value(value);
            record
        });
        true
    }

    fn del(&self, key: &[u8]) {
        self.delete(key, false);
    }

    fn set_expiry(&self, key: &[u8], expiry_seconds: i32) {
        self.replace(key, "setExpiry", |mut record| {
            record.set_expiry(expiry_seconds);
            record
        });
    }

    fn resolve_first(&self, var: &[u8]) -> Option<Vec<u8>> {
        let mut ret = None;
        let mut collection_data = CollectionData::default();

        match self.txn_begin(true) {
            Err(rc) => lmdb_debug(rc, "txn", "resolveFirst"),
            Ok(txn) => {
                match txn.get(var) {
                    Ok(value) => {
                        collection_data = CollectionData::from_bytes(value);
                        if !collection_data.is_expired() {
                            ret = collection_data.value.take();
                        }
                    }
                    Err(rc) => lmdb_debug(rc, "get", "resolveFirst"),
                }
                drop(txn); // mdb_txn_abort
            }
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
            self.walk("resolveMultiMatches", |k, d| {
                l.push(VariableValue::with_collection(name, k, d));
            });
        } else {
            self.walk("resolveMultiMatches", |k, d| {
                if key_matches_prefix(var, k) {
                    l.push(VariableValue::with_collection(name, k, d));
                }
            });
        }
        move_to_front_reversed(l, start);
    }

    fn resolve_regex(&self, r: &Regex, l: &mut Vec<VariableValue>, ke: &KeyExclusions) {
        let start = l.len();
        self.walk("resolveRegularExpression", |k, d| {
            if r.search(k) <= 0 {
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
    fn prefix_match() {
        assert!(key_matches_prefix(b"ab", b"abc"));
        assert!(key_matches_prefix(b"abc", b"abc"));
        assert!(!key_matches_prefix(b"abcd", b"abc"));
        assert!(!key_matches_prefix(b"abd", b"abc"));
        assert!(key_matches_prefix(b"a\0z", b"a\0c"));
    }

    #[test]
    fn store_resolve_expiry_regex() {
        provider_in_temp_dir();
        let p = format!("t{}_{}", std::process::id(), crate::utils::system::now());
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
        let re = format!("^{}::A", p.to_uppercase());
        c.resolve_regular_expression(re.as_bytes(), &mut l, &KeyExclusions::default());
        assert_eq!(keys(&l), vec![k("ab"), k("a")]);
        assert_eq!(l[0].key_with_collection(), k("ab").as_slice());

        // delete
        c.del(&k("a"));
        assert_eq!(c.resolve_first(&k("a")), None);
        c.del(&k("ab"));
        c.del(&k("noval"));
    }
}
