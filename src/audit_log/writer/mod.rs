//! `audit_log::writer` (mirrors `src/audit_log/writer/`).

pub mod https;
pub mod parallel;
pub mod serial;
// Mirrors the C++ layout (`writer/writer.h|cc`).
#[allow(clippy::module_inception)]
pub mod writer;
