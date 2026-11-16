//! The storage backends of the persistent collections.

pub mod collection_data;
// The backend of the persistent collections in builds without LMDB.
pub mod in_memory_per_process;
pub mod lmdb;
