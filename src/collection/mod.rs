//! `collection` (mirrors `src/collection/`).

pub mod backend;
// Mirrors the C++ layout (`collection/collection.h|cc`).
#[allow(clippy::module_inception)]
pub mod collection;
pub mod collections;
