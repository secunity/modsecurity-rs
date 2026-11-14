//! `collection::backend` (mirrors `src/collection/backend/`).

pub mod collection_data;
pub mod in_memory_per_process;
// LMDB.
#[allow(unsafe_code)]
pub mod lmdb;
