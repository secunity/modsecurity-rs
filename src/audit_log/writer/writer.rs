//! Port of `src/audit_log/writer/writer.cc`, `src/audit_log/writer/writer.h`.

use crate::audit_log::audit_log::AuditLog;
use crate::transaction::Transaction;

pub const SERIAL_AUDIT_LOG_BOUNDARY_LENGTH: usize = 8;

/// An audit log writer (serial file, parallel directory tree or HTTPS).
///
/// The C++ writers hold a back pointer to the `AuditLog` that owns them
/// (`m_audit`); the owner passes itself as `audit` to every call instead.
/// Errors are the C++ `std::string *error` out-parameter.
pub trait Writer: Send + Sync {
    fn init(&self, audit: &AuditLog) -> Result<(), String>;

    fn write(&self, audit: &AuditLog, transaction: &Transaction<'_>, parts: i32) -> Result<(), String>;

    /// The C++ destructor: releases the shared files, looked up through the
    /// owner's current configuration.
    fn close(&self, audit: &AuditLog);
}

/// `Writer::generateBoundary`: `SERIAL_AUDIT_LOG_BOUNDARY_LENGTH` random
/// alphanumeric characters, from the C library `rand()` as in C++.
pub fn generate_boundary(boundary: &mut String) {
    const ALPHANUM: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    for _ in 0..SERIAL_AUDIT_LOG_BOUNDARY_LENGTH {
        // SAFETY: rand() has no preconditions.
        let r = unsafe { libc::rand() } as usize;
        boundary.push(ALPHANUM[r % ALPHANUM.len()] as char);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundary_is_alphanumeric() {
        let mut b = String::new();
        generate_boundary(&mut b);
        assert_eq!(b.len(), SERIAL_AUDIT_LOG_BOUNDARY_LENGTH);
        assert!(b.bytes().all(|c| c.is_ascii_alphanumeric()));
    }
}
