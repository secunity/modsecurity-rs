//! Port of `src/audit_log/writer/serial.cc`, `src/audit_log/writer/serial.h`.

use crate::audit_log::audit_log::{AuditLog, AuditLogFormat};
use crate::audit_log::writer::writer::{Writer, generate_boundary};
use crate::transaction::Transaction;
use crate::utils::shared_files::SharedFiles;

/// Appends every entry to the single file `SecAuditLog` (`path1`).
#[derive(Debug, Default)]
pub struct Serial;

impl Serial {
    pub fn new() -> Self {
        Serial
    }
}

impl Writer for Serial {
    fn init(&self, audit: &AuditLog) -> Result<(), String> {
        let mut error = String::new();
        if SharedFiles::get_instance().open(&audit.path1, &mut error) { Ok(()) } else { Err(error) }
    }

    fn write(&self, audit: &AuditLog, transaction: &Transaction<'_>, parts: i32) -> Result<(), String> {
        // As in C++, the format comes from the transaction's rule set.
        let msg = if transaction.rules.properties.audit_log.format == AuditLogFormat::JSONAuditLogFormat {
            transaction.to_json(parts)
        } else {
            let mut boundary = String::new();
            generate_boundary(&mut boundary);
            transaction.to_old_audit_log_format(parts, &format!("-{}--", boundary), &audit.prefix)
        };

        let mut error = String::new();
        if SharedFiles::get_instance().write(&audit.path1, &msg, &mut error) { Ok(()) } else { Err(error) }
    }

    fn close(&self, audit: &AuditLog) {
        SharedFiles::get_instance().close(&audit.path1);
    }
}
