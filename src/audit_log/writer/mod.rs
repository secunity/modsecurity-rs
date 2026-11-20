//! The audit log writers: serial file, parallel directory tree and HTTPS.

pub mod https;
pub mod parallel;
pub mod serial;

use std::sync::Arc;

use crate::audit_log::{AuditLog, AuditLogType, Parts, SetupError};
use crate::transaction::Transaction;
use crate::utils::shared_files::SharedFile;

pub const SERIAL_AUDIT_LOG_BOUNDARY_LENGTH: usize = 8;

/// An audit log writer (serial file, parallel directory tree or HTTPS),
/// with the files it opened (closed when it is dropped).
#[derive(Debug)]
pub enum Writer {
    /// Every entry goes to `SecAuditLog`.
    Serial {
        log: Arc<SharedFile>,
    },
    /// Every entry goes to its own file; the index lines to `SecAuditLog2`,
    /// or else `SecAuditLog` (both are opened when set).
    Parallel {
        log: Option<Arc<SharedFile>>,
        log2: Option<Arc<SharedFile>>,
    },
    Https,
}

impl Writer {
    /// Creates the writer of `SecAuditLogType` (serial when not set) and
    /// opens what it needs.
    pub fn open(audit: &AuditLog) -> Result<Self, SetupError> {
        match audit.audit_type {
            Some(AuditLogType::Parallel) => parallel::open(audit),
            Some(AuditLogType::Https) => Ok(Writer::Https),
            Some(AuditLogType::Serial) | None => serial::open(audit),
        }
    }

    /// Saves the `parts` of `transaction`.
    pub fn write(&self, audit: &AuditLog, transaction: &Transaction<'_>, parts: Parts) -> Result<(), String> {
        match self {
            Writer::Serial { log } => serial::write(log, audit, transaction, parts),
            Writer::Parallel { log, log2 } => {
                parallel::write(log2.as_ref().or(log.as_ref()), audit, transaction, parts)
            }
            Writer::Https => https::write(audit, transaction, parts),
        }
    }
}

/// A boundary of `SERIAL_AUDIT_LOG_BOUNDARY_LENGTH` random alphanumeric
/// characters, from the `rand` crate's thread local generator. The C
/// library `rand()` is not used, so creating an engine does not reseed the
/// host process's `rand()`.
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
