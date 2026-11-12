//! Port of `src/collection/backend/lmdb.cc`, `src/collection/backend/lmdb.h`.
//!
//! Persistent collections (`IP`, `SESSION`, `USER`, `GLOBAL`, `RESOURCE`)
//! stored in an LMDB file shared by every process using the library:
//! `./modsec-shared-collections` (relative to the working directory).
//! Values are stored as `CollectionData::serialize` (value + expiry).
//!
//! All the `unsafe` code of the backend (the LMDB C API) lives in this
//! file; every LMDB handle is created, used and released within one method,
//! except the environment and the database handle, which live for the
//! whole process (`MdbEnvProvider`).
#![cfg(feature = "lmdb")]

use std::ffi::CStr;
use std::os::raw::{c_int, c_uint};
use std::ptr;
use std::sync::OnceLock;

use lmdb_master_sys as ffi;
use lmdb_master_sys::{MDB_dbi, MDB_env, MDB_txn, MDB_val};

use crate::collection::Collection;
use crate::collection::backend::collection_data::CollectionData;
use crate::utils::regex::Regex;
use crate::variable_value::{VariableValue, move_to_front_reversed};
use crate::variables::variable::KeyExclusions;

/// The C++ `#undef LMDB_STDOUT_COUT`: the LMDB failures are not printed.
const LMDB_STDOUT_COUT: bool = false;

/// The location of the shared collections file.
const SHARED_COLLECTIONS_PATH: &CStr = c"./modsec-shared-collections";

/// The MDBEnvProvider is a singleton: the LMDB environment and its single
/// (unnamed) database, opened on first use and shared by every collection.
struct MdbEnvProvider {
    env: *mut MDB_env,
    dbi: MDB_dbi,
    valid: bool,
}

// SAFETY: an LMDB environment handle may be used concurrently by several
// threads (each with its own transactions), and the dbi is a plain integer
// handle valid for the life of the environment; neither is modified after
// construction.
unsafe impl Send for MdbEnvProvider {}
// SAFETY: see above.
unsafe impl Sync for MdbEnvProvider {}

static ENV_PROVIDER: OnceLock<MdbEnvProvider> = OnceLock::new();

impl MdbEnvProvider {
    /// `GetInstance` (the Meyers singleton).
    fn instance() -> &'static MdbEnvProvider {
        ENV_PROVIDER.get_or_init(|| MdbEnvProvider::open(SHARED_COLLECTIONS_PATH))
    }

    /// The C++ constructor.
    fn open(path: &CStr) -> MdbEnvProvider {
        let mut env: *mut MDB_env = ptr::null_mut();
        let mut dbi: MDB_dbi = 0;
        let mut valid = false;

        // SAFETY: `env` is a valid out pointer.
        if unsafe { ffi::mdb_env_create(&mut env) } != 0 {
            return MdbEnvProvider { env: ptr::null_mut(), dbi, valid };
        }
        // SAFETY: `env` was just created and `path` is NUL terminated.
        let rc = unsafe { ffi::mdb_env_open(env, path.as_ptr(), ffi::MDB_NOSUBDIR, 0o664) };

        if rc == 0 {
            valid = true;
            let mut txn: *mut MDB_txn = ptr::null_mut();
            // SAFETY: `env` is open; `txn` and `dbi` are valid out pointers.
            // The txn is committed (which frees it) right away.
            unsafe {
                if ffi::mdb_txn_begin(env, ptr::null_mut(), 0, &mut txn) == 0 {
                    ffi::mdb_dbi_open(txn, ptr::null(), ffi::MDB_CREATE | ffi::MDB_DUPSORT, &mut dbi);
                    ffi::mdb_txn_commit(txn);
                }
            }
        } else {
            // A failed open must be discarded with mdb_env_close.
            // SAFETY: `env` was created above and is not used afterwards.
            unsafe { ffi::mdb_env_close(env) };
            env = ptr::null_mut();
        }

        // The C++ destructor (mdb_dbi_close + mdb_env_close at exit) has no
        // equivalent: the singleton lives until the process ends.
        MdbEnvProvider { env, dbi, valid }
    }

    fn is_valid(&self) -> bool {
        self.valid
    }
}

/// An LMDB transaction, aborted on drop unless committed.
struct Txn {
    ptr: *mut MDB_txn,
}

impl Txn {
    /// `mdb_txn_commit`; LMDB frees the transaction whatever the result.
    fn commit(self) -> c_int {
        let p = self.ptr;
        std::mem::forget(self);
        // SAFETY: `p` is a live transaction, not used after this call.
        unsafe { ffi::mdb_txn_commit(p) }
    }
}

impl Drop for Txn {
    fn drop(&mut self) {
        // SAFETY: `ptr` is a live transaction (commit forgets `self`).
        unsafe { ffi::mdb_txn_abort(self.ptr) };
    }
}

/// `string2val`: an `MDB_val` pointing at `s` (LMDB only reads it).
fn string2val(s: &[u8]) -> MDB_val {
    MDB_val { mv_size: s.len(), mv_data: s.as_ptr() as *mut _ }
}

fn empty_val() -> MDB_val {
    MDB_val { mv_size: 0, mv_data: ptr::null_mut() }
}

/// The bytes of a value returned by LMDB.
///
/// # Safety
/// `v` must come from LMDB within a transaction that is still open, and the
/// slice must not be used after that transaction ends or the database is
/// written.
unsafe fn val_bytes<'a>(v: &MDB_val) -> &'a [u8] {
    if v.mv_size == 0 || v.mv_data.is_null() {
        return &[];
    }
    // SAFETY: guaranteed by the caller: LMDB values point at `mv_size`
    // readable bytes while their transaction lives.
    unsafe { std::slice::from_raw_parts(v.mv_data as *const u8, v.mv_size) }
}

/// The C++ `strncmp(var.c_str(), key, var.size()) == 0`: `key` starts with
/// `var` (up to a NUL byte in `var`).
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

/// `lmdb_debug`: describes an LMDB failure on stdout (compiled out, as in
/// C++, unless `LMDB_STDOUT_COUT` is set).
fn lmdb_debug(rc: c_int, op: &str, scope: &str) {
    if !LMDB_STDOUT_COUT || rc == 0 {
        return;
    }

    let msg = match op {
        "txn" => {
            let detail = match rc {
                ffi::MDB_PANIC => {
                    "panic: a fatal error occurred earlier and the environment must be shut down.".to_string()
                }
                ffi::MDB_MAP_RESIZED => {
                    "map resized: another process wrote data beyond this MDB_env's mapsize and this \
                                         environment's map must be resized as well. See mdb_env_set_mapsize()."
                        .to_string()
                }
                ffi::MDB_READERS_FULL => "max readers: a read-only transaction was requested and the reader lock \
                                          table is full. See mdb_env_set_maxreaders()."
                    .to_string(),
                libc::ENOMEM => "out of memory.".to_string(),
                _ => format!("not sure what is wrong, code: {}", rc),
            };
            format!("{}, LMDB failure while starting txn: {}", scope, detail)
        }
        "get" => {
            let detail = match rc {
                ffi::MDB_NOTFOUND => "not found: the key was not in the database.",
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

    /// `txn_begin`: opens the shared environment on first use; -1 when it
    /// could not be opened.
    fn txn_begin(&self, flags: c_uint) -> Result<(Txn, MDB_dbi), c_int> {
        let provider = MdbEnvProvider::instance();
        if !provider.is_valid() {
            return Err(-1);
        }
        let mut txn: *mut MDB_txn = ptr::null_mut();
        // SAFETY: the environment is open; `txn` is a valid out pointer.
        let rc = unsafe { ffi::mdb_txn_begin(provider.env, ptr::null_mut(), flags, &mut txn) };
        if rc != 0 {
            return Err(rc);
        }
        Ok((Txn { ptr: txn }, provider.dbi))
    }

    /// Writes `key` with the value computed from its previous data (if any)
    /// in one write transaction: the shared body of `storeOrUpdateFirst`,
    /// `updateFirst` and `setExpiry`. `must_exist` makes a missing key an
    /// error (`updateFirst`). Returns the last LMDB code (0 on success).
    fn replace(
        &self,
        key: &[u8],
        scope: &str,
        must_exist: bool,
        build: impl FnOnce(CollectionData) -> CollectionData,
    ) -> c_int {
        let (txn, dbi) = match self.txn_begin(0) {
            Ok(t) => t,
            Err(rc) => {
                lmdb_debug(rc, "txn", scope);
                return rc;
            }
        };

        let mut mdb_key = string2val(key);
        let mut mdb_value_ret = empty_val();
        let mut previous_data = CollectionData::new();

        // SAFETY: live write txn, valid dbi and MDB_vals.
        let rc = unsafe { ffi::mdb_get(txn.ptr, dbi, &mut mdb_key, &mut mdb_value_ret) };
        lmdb_debug(rc, "get", scope);
        if rc == 0 {
            // SAFETY: the value belongs to the open txn and is copied
            // before the database is modified.
            previous_data.deserialize(unsafe { val_bytes(&mdb_value_ret) });
            // SAFETY: as above; deletes the pair just read.
            let rc = unsafe { ffi::mdb_del(txn.ptr, dbi, &mut mdb_key, &mut mdb_value_ret) };
            lmdb_debug(rc, "del", scope);
            if rc != 0 {
                return rc;
            }
        } else if must_exist {
            return rc;
        }

        let new_data = build(previous_data);
        let serialized_data = new_data.serialize();
        let mut mdb_value = string2val(&serialized_data);

        // SAFETY: live write txn; key and value point at live buffers.
        let rc = unsafe { ffi::mdb_put(txn.ptr, dbi, &mut mdb_key, &mut mdb_value, 0) };
        lmdb_debug(rc, "put", scope);
        if rc != 0 {
            return rc;
        }

        let rc = txn.commit();
        lmdb_debug(rc, "commit", scope);
        rc
    }

    /// `delIfExpired`
    fn del_if_expired(&self, key: &[u8]) {
        let (txn, dbi) = match self.txn_begin(0) {
            Ok(t) => t,
            Err(rc) => {
                lmdb_debug(rc, "txn", "del");
                return;
            }
        };

        let mut mdb_key = string2val(key);
        let mut mdb_value_ret = empty_val();

        // SAFETY: live write txn, valid dbi and MDB_vals.
        let rc = unsafe { ffi::mdb_get(txn.ptr, dbi, &mut mdb_key, &mut mdb_value_ret) };
        lmdb_debug(rc, "get", "del");
        if rc != 0 {
            return;
        }

        let mut collection_data = CollectionData::new();
        // SAFETY: the value belongs to the open txn and is copied.
        collection_data.deserialize(unsafe { val_bytes(&mdb_value_ret) });
        if collection_data.is_expired() {
            // SAFETY: deletes the pair just read in the live write txn.
            let rc = unsafe { ffi::mdb_del(txn.ptr, dbi, &mut mdb_key, &mut mdb_value_ret) };
            lmdb_debug(rc, "del", "del");
            if rc != 0 {
                return;
            }
        }

        let rc = txn.commit();
        lmdb_debug(rc, "commit", "del");
    }

    /// Walks the database with a cursor in a read-only transaction, calling
    /// `f(key, data)` for every non expired entry holding a value; the
    /// expired entries are deleted afterwards (`delIfExpired`).
    ///
    /// `op` is the cursor operation; `start_key` the key given to the first
    /// `mdb_cursor_get` (only `resolveSingleMatch` passes one, and LMDB
    /// ignores it for the "next" operations).
    fn walk(
        &self,
        scope: &str,
        op: ffi::MDB_cursor_op,
        start_key: Option<&[u8]>,
        mut f: impl FnMut(&[u8], &CollectionData),
    ) {
        let mut expired_vars: Vec<Vec<u8>> = Vec::new();

        match self.txn_begin(ffi::MDB_RDONLY) {
            Err(rc) => lmdb_debug(rc, "txn", scope),
            Ok((txn, dbi)) => {
                let mut cursor: *mut ffi::MDB_cursor = ptr::null_mut();
                // SAFETY: live txn, valid dbi, valid out pointer.
                let rc = unsafe { ffi::mdb_cursor_open(txn.ptr, dbi, &mut cursor) };
                lmdb_debug(rc, "cursor_open", scope);
                if rc == 0 {
                    let mut key = start_key.map(string2val).unwrap_or_else(empty_val);
                    let mut data = empty_val();
                    let mut collection_data = CollectionData::new();
                    // SAFETY: the cursor belongs to the live txn; the
                    // returned key/data are only read before the next
                    // cursor call.
                    while unsafe { ffi::mdb_cursor_get(cursor, &mut key, &mut data, op) } == 0 {
                        // SAFETY: as above.
                        let (k, d) = unsafe { (val_bytes(&key), val_bytes(&data)) };
                        collection_data.deserialize(d);
                        if collection_data.is_expired() {
                            expired_vars.push(k.to_vec());
                            continue;
                        }
                        if !collection_data.has_value() {
                            continue;
                        }
                        f(k, &collection_data);
                    }
                    // SAFETY: the cursor is closed before its txn ends.
                    unsafe { ffi::mdb_cursor_close(cursor) };
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
    fn name(&self) -> &str {
        &self.name
    }

    fn store_or_update_first(&self, key: &[u8], value: &[u8]) -> bool {
        self.replace(key, "storeOrUpdateFirst", false, |previous_data| {
            let mut new_data = if previous_data.has_expiry() { previous_data } else { CollectionData::new() };
            new_data.set_value(value);
            new_data
        });
        true
    }

    fn update_first(&self, key: &[u8], value: &[u8]) -> bool {
        let rc = self.replace(key, "updateFirst", true, |previous_data| {
            let mut new_data = if previous_data.has_expiry() { previous_data } else { CollectionData::new() };
            new_data.set_value(value);
            new_data
        });
        rc == 0
    }

    fn del(&self, key: &[u8]) {
        let (txn, dbi) = match self.txn_begin(0) {
            Ok(t) => t,
            Err(rc) => {
                lmdb_debug(rc, "txn", "del");
                return;
            }
        };

        let mut mdb_key = string2val(key);
        let mut mdb_value_ret = empty_val();

        // SAFETY: live write txn, valid dbi and MDB_vals.
        let rc = unsafe { ffi::mdb_get(txn.ptr, dbi, &mut mdb_key, &mut mdb_value_ret) };
        lmdb_debug(rc, "get", "del");
        if rc != 0 {
            return;
        }

        // SAFETY: deletes the pair just read in the live write txn.
        let rc = unsafe { ffi::mdb_del(txn.ptr, dbi, &mut mdb_key, &mut mdb_value_ret) };
        lmdb_debug(rc, "del", "del");
        if rc != 0 {
            return;
        }

        let rc = txn.commit();
        lmdb_debug(rc, "commit", "del");
    }

    fn set_expiry(&self, key: &[u8], expiry_seconds: i32) {
        self.replace(key, "setExpiry", false, |previous_data| {
            let mut new_data = if previous_data.has_value() { previous_data } else { CollectionData::new() };
            new_data.set_expiry(expiry_seconds);
            new_data
        });
    }

    fn resolve_first(&self, var: &[u8]) -> Option<Vec<u8>> {
        let mut ret = None;
        let mut collection_data = CollectionData::new();

        match self.txn_begin(ffi::MDB_RDONLY) {
            Err(rc) => lmdb_debug(rc, "txn", "resolveFirst"),
            Ok((txn, dbi)) => {
                let mut mdb_key = string2val(var);
                let mut mdb_value_ret = empty_val();
                // SAFETY: live txn, valid dbi and MDB_vals.
                let rc = unsafe { ffi::mdb_get(txn.ptr, dbi, &mut mdb_key, &mut mdb_value_ret) };
                lmdb_debug(rc, "get", "resolveFirst");
                if rc == 0 {
                    // SAFETY: the value belongs to the open txn and is copied.
                    collection_data.deserialize(unsafe { val_bytes(&mdb_value_ret) });
                    if !collection_data.is_expired() && collection_data.has_value() {
                        ret = Some(collection_data.value().to_vec());
                    }
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

    /// Quirk (C++): the cursor is never positioned on `var` (the first
    /// `MDB_NEXT_DUP` on a fresh cursor returns the first entry of the
    /// database), and the result is named after `var`.
    fn resolve_single_match(&self, var: &[u8], l: &mut Vec<VariableValue>) {
        self.walk("resolveSingleMatch", ffi::MDB_NEXT_DUP, Some(var), |_k, d| {
            l.push(VariableValue::new(var, d.value()));
        });
    }

    /// Quirk (C++): the key exclusions are not applied, and a non empty
    /// `var` selects every key it prefixes.
    fn resolve_multi_matches(&self, var: &[u8], l: &mut Vec<VariableValue>, _ke: &KeyExclusions) {
        let name = self.name.as_bytes();
        let start = l.len();
        if var.is_empty() {
            self.walk("resolveMultiMatches", ffi::MDB_NEXT, None, |k, d| {
                l.push(VariableValue::with_collection(name, k, d.value()));
            });
        } else {
            self.walk("resolveMultiMatches", ffi::MDB_NEXT, None, |k, d| {
                if key_matches_prefix(var, k) {
                    l.push(VariableValue::with_collection(name, k, d.value()));
                }
            });
        }
        move_to_front_reversed(l, start);
    }

    fn resolve_regex(&self, r: &Regex, l: &mut Vec<VariableValue>, ke: &KeyExclusions) {
        let start = l.len();
        self.walk("resolveRegularExpression", ffi::MDB_NEXT, None, |k, d| {
            if r.search(k) <= 0 {
                return;
            }
            if ke.to_omit(k) {
                return;
            }
            l.push(VariableValue::new(k, d.value()));
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
        ENV_PROVIDER.get_or_init(|| MdbEnvProvider::open(&path));
        assert!(MdbEnvProvider::instance().is_valid());
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
        assert!(c.update_first(&k("a"), b"2"));
        assert_eq!(c.resolve_first(&k("a")), Some(b"2".to_vec()));
        assert!(!c.update_first(&k("missing"), b"x"));
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
        assert!(!c.update_first(&k("b"), b"x"), "expired key was deleted");

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
