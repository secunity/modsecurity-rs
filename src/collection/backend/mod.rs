//! `collection::backend` (mirrors `src/collection/backend/`).

pub mod collection_data;
// The backend of the persistent collections in builds without LMDB.
#[cfg_attr(feature = "lmdb", allow(dead_code))]
pub mod in_memory_per_process;
// LMDB.
#[allow(unsafe_code)]
pub mod lmdb;
