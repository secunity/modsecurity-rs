//! LMDB: the environment of the persistent collections, its transactions
//! and cursors.
//!
//! The environment holds one unnamed database (`MDB_DUPSORT`). It is a
//! process singleton because LMDB requires it: an environment must not be
//! opened twice in one process. Transactions and cursors release their
//! handles when dropped; values borrowed from a transaction cannot outlive
//! it or a later write to it (the borrow checker enforces both).

use std::ffi::{CStr, c_int, c_uint};
use std::marker::PhantomData;
use std::ptr;
use std::sync::OnceLock;

use lmdb_master_sys as ffi;
use lmdb_master_sys::{MDB_dbi, MDB_env, MDB_txn, MDB_val};

/// An LMDB return code (0 for success, an `MDB_*` code or an errno).
pub type Code = c_int;

pub use lmdb_master_sys::{MDB_MAP_RESIZED, MDB_NOTFOUND, MDB_PANIC, MDB_READERS_FULL};

/// The open environment and its database.
pub struct Environment {
    env: *mut MDB_env,
    dbi: MDB_dbi,
}

// SAFETY: an LMDB environment handle may be used concurrently by several
// threads (each with its own transactions), and the dbi is a plain integer
// handle valid for the life of the environment; neither is modified after
// construction.
unsafe impl Send for Environment {}
// SAFETY: see above.
unsafe impl Sync for Environment {}

static SHARED: OnceLock<Option<Environment>> = OnceLock::new();

impl Environment {
    /// The environment of the process, opened at `path` on first use (later
    /// calls get that one, whatever their path); `None` when it could not
    /// be opened.
    pub fn shared(path: &CStr) -> Option<&'static Environment> {
        SHARED.get_or_init(|| Environment::open(path)).as_ref()
    }

    /// Opens the environment at `path` (one file, `MDB_NOSUBDIR`) and its
    /// database. The environment is never closed: it lives as long as the
    /// process, and `mdb_env_close` is not called at exit.
    fn open(path: &CStr) -> Option<Environment> {
        let mut env: *mut MDB_env = ptr::null_mut();
        let mut dbi: MDB_dbi = 0;

        // SAFETY: `env` is a valid out pointer.
        if unsafe { ffi::mdb_env_create(&mut env) } != 0 {
            return None;
        }
        // SAFETY: `env` was just created and `path` is NUL terminated.
        let rc = unsafe { ffi::mdb_env_open(env, path.as_ptr(), ffi::MDB_NOSUBDIR, 0o664) };
        if rc != 0 {
            // A failed open must be discarded with mdb_env_close.
            // SAFETY: `env` was created above and is not used afterwards.
            unsafe { ffi::mdb_env_close(env) };
            return None;
        }
        let mut txn: *mut MDB_txn = ptr::null_mut();
        // SAFETY: `env` is open; `txn` and `dbi` are valid out pointers. The
        // txn is committed (which frees it) right away.
        unsafe {
            if ffi::mdb_txn_begin(env, ptr::null_mut(), 0, &mut txn) == 0 {
                ffi::mdb_dbi_open(txn, ptr::null(), ffi::MDB_CREATE | ffi::MDB_DUPSORT, &mut dbi);
                ffi::mdb_txn_commit(txn);
            }
        }
        Some(Environment { env, dbi })
    }

    /// Begins a transaction (`mdb_txn_begin`), read-only or read-write.
    pub fn begin(&self, read_only: bool) -> Result<Txn<'_>, Code> {
        let flags: c_uint = if read_only { ffi::MDB_RDONLY } else { 0 };
        let mut txn: *mut MDB_txn = ptr::null_mut();
        // SAFETY: the environment is open; `txn` is a valid out pointer.
        let rc = unsafe { ffi::mdb_txn_begin(self.env, ptr::null_mut(), flags, &mut txn) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(Txn { ptr: txn, dbi: self.dbi, _env: PhantomData })
    }
}

/// An `MDB_val` pointing at `s` (LMDB only reads it).
fn val(s: &[u8]) -> MDB_val {
    MDB_val { mv_size: s.len(), mv_data: s.as_ptr() as *mut _ }
}

fn empty_val() -> MDB_val {
    MDB_val { mv_size: 0, mv_data: ptr::null_mut() }
}

/// The bytes of a value returned by LMDB, borrowed for `'a`.
///
/// # Safety
/// `v` must come from LMDB within a transaction that stays open, and not
/// be written, for `'a`.
unsafe fn bytes<'a>(v: &MDB_val) -> &'a [u8] {
    if v.mv_size == 0 || v.mv_data.is_null() {
        return &[];
    }
    // SAFETY: guaranteed by the caller: LMDB values point at `mv_size`
    // readable bytes while their transaction lives unmodified.
    unsafe { std::slice::from_raw_parts(v.mv_data as *const u8, v.mv_size) }
}

/// A transaction, aborted on drop unless committed.
pub struct Txn<'env> {
    ptr: *mut MDB_txn,
    dbi: MDB_dbi,
    _env: PhantomData<&'env Environment>,
}

impl Txn<'_> {
    /// The first value of `key` (`mdb_get`), valid until the transaction
    /// is written or ends.
    pub fn get(&self, key: &[u8]) -> Result<&[u8], Code> {
        let mut k = val(key);
        let mut v = empty_val();
        // SAFETY: live txn, valid dbi; `k` points at `key`, `v` is an out
        // value.
        let rc = unsafe { ffi::mdb_get(self.ptr, self.dbi, &mut k, &mut v) };
        if rc != 0 {
            return Err(rc);
        }
        // SAFETY: `v` comes from this transaction, which `&self` keeps open
        // and unwritten (writes take `&mut self`).
        Ok(unsafe { bytes(&v) })
    }

    /// Deletes the pair `key` = `value` (`mdb_del`; with `MDB_DUPSORT`, the
    /// duplicate with that content).
    pub fn del(&mut self, key: &[u8], value: &[u8]) -> Result<(), Code> {
        let (mut k, mut v) = (val(key), val(value));
        // SAFETY: live txn and dbi; LMDB only reads `k` and `v`.
        match unsafe { ffi::mdb_del(self.ptr, self.dbi, &mut k, &mut v) } {
            0 => Ok(()),
            rc => Err(rc),
        }
    }

    /// Stores `value` under `key` (`mdb_put`, no flags).
    pub fn put(&mut self, key: &[u8], value: &[u8]) -> Result<(), Code> {
        let (mut k, mut v) = (val(key), val(value));
        // SAFETY: live txn and dbi; LMDB copies the bytes `k` and `v` point
        // at.
        match unsafe { ffi::mdb_put(self.ptr, self.dbi, &mut k, &mut v, 0) } {
            0 => Ok(()),
            rc => Err(rc),
        }
    }

    /// Commits the transaction (`mdb_txn_commit`); LMDB frees it whatever
    /// the result.
    pub fn commit(self) -> Result<(), Code> {
        let p = self.ptr;
        std::mem::forget(self);
        // SAFETY: `p` is a live transaction, not used after this call.
        match unsafe { ffi::mdb_txn_commit(p) } {
            0 => Ok(()),
            rc => Err(rc),
        }
    }

    /// A cursor at the start of the database.
    pub fn cursor(&self) -> Result<Cursor<'_>, Code> {
        let mut ptr = ptr::null_mut();
        // SAFETY: live txn and dbi; `ptr` is a valid out pointer. Only a
        // successful open builds a Cursor.
        let rc = unsafe { ffi::mdb_cursor_open(self.ptr, self.dbi, &mut ptr) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(Cursor { ptr, _txn: PhantomData })
    }
}

impl Drop for Txn<'_> {
    fn drop(&mut self) {
        // SAFETY: `ptr` is a live transaction (commit forgets `self`).
        unsafe { ffi::mdb_txn_abort(self.ptr) };
    }
}

/// A cursor, closed before its transaction can end (it borrows it).
pub struct Cursor<'txn> {
    ptr: *mut ffi::MDB_cursor,
    _txn: PhantomData<&'txn Txn<'txn>>,
}

impl Cursor<'_> {
    /// The next pair (`MDB_NEXT`), valid until the next cursor operation.
    /// Unlike seek operations, this returns keys owned by LMDB, never the
    /// caller's buffers.
    #[allow(clippy::should_implement_trait)] // The items borrow the cursor.
    pub fn next(&mut self) -> Result<(&[u8], &[u8]), Code> {
        let mut key = empty_val();
        let mut data = empty_val();
        // SAFETY: the cursor and its transaction are live; both output
        // values remain valid throughout the call.
        let rc = unsafe { ffi::mdb_cursor_get(self.ptr, &mut key, &mut data, ffi::MDB_NEXT) };
        if rc != 0 {
            return Err(rc);
        }
        // SAFETY: LMDB returned these values in the borrowed (read-only for
        // as long as the cursor borrows it) transaction; the mutable cursor
        // borrow prevents advancing while they are used.
        unsafe { Ok((bytes(&key), bytes(&data))) }
    }
}

impl Drop for Cursor<'_> {
    fn drop(&mut self) {
        // SAFETY: successfully opened, uniquely owned, and the borrowed
        // transaction is still open.
        unsafe { ffi::mdb_cursor_close(self.ptr) };
    }
}
