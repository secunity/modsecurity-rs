//! Port of `src/audit_log/writer/writer.cc`, `src/audit_log/writer/writer.h`.

pub mod https;
pub mod parallel;
pub mod serial;

use crate::audit_log::{AuditLog, AuditLogType};
use crate::transaction::Transaction;

pub const SERIAL_AUDIT_LOG_BOUNDARY_LENGTH: usize = 8;

/// An audit log writer (serial file, parallel directory tree or HTTPS).
///
/// The C++ writers hold a back pointer to the `AuditLog` that owns them
/// (`m_audit`); the owner passes itself as `audit` to every call instead.
/// They have no state of their own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Writer {
    Serial,
    Parallel,
    Https,
}

impl Writer {
    /// The writer of `SecAuditLogType` (serial when not set).
    pub fn for_type(audit_type: Option<AuditLogType>) -> Self {
        match audit_type {
            Some(AuditLogType::Parallel) => Writer::Parallel,
            Some(AuditLogType::Https) => Writer::Https,
            Some(AuditLogType::Serial) | None => Writer::Serial,
        }
    }

    /// `init`: opens what the writer needs.
    pub fn init(self, audit: &AuditLog) -> Result<(), String> {
        match self {
            Writer::Serial => serial::init(audit),
            Writer::Parallel => parallel::init(audit),
            Writer::Https => Ok(()),
        }
    }

    /// `write`: saves the `parts` of `transaction`.
    pub fn write(self, audit: &AuditLog, transaction: &Transaction<'_>, parts: i32) -> Result<(), String> {
        match self {
            Writer::Serial => serial::write(audit, transaction, parts),
            Writer::Parallel => parallel::write(audit, transaction, parts),
            Writer::Https => https::write(audit, transaction, parts),
        }
    }

    /// The C++ destructor: releases the shared files, looked up through the
    /// owner's current configuration.
    pub fn close(self, audit: &AuditLog) {
        match self {
            Writer::Serial => serial::close(audit),
            Writer::Parallel => parallel::close(audit),
            Writer::Https => {}
        }
    }
}

/// `Writer::generateBoundary`: `SERIAL_AUDIT_LOG_BOUNDARY_LENGTH` random
/// alphanumeric characters. The C++ code uses the C library `rand()` (seeded
/// with `srand(time(NULL))` by the `ModSecurity` constructor); the `rand`
/// crate's thread local generator is used instead, so creating an engine no
/// longer reseeds the host process's `rand()`.
pub fn generate_boundary() -> String {
    use rand::Rng;
    const ALPHANUM: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    let mut rng = rand::rng();
    (0..SERIAL_AUDIT_LOG_BOUNDARY_LENGTH).map(|_| char::from(ALPHANUM[rng.random_range(0..ALPHANUM.len())])).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundary_is_alphanumeric() {
        let b = generate_boundary();
        assert_eq!(b.len(), SERIAL_AUDIT_LOG_BOUNDARY_LENGTH);
        assert!(b.bytes().all(|c| c.is_ascii_alphanumeric()));
    }
}
