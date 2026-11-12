//! Port of `src/audit_log/writer/serial.cc`, `src/audit_log/writer/serial.h`.
//!
//! The serial writer appends every entry to the single file `SecAuditLog`
//! (`path1`).

use crate::audit_log::audit_log::{AuditLog, AuditLogFormat};
use crate::audit_log::writer::writer::generate_boundary;
use crate::transaction::Transaction;
use crate::utils::shared_files::SharedFiles;

pub(super) fn init(audit: &AuditLog) -> Result<(), String> {
    SharedFiles::get_instance().open(&audit.path1)
}

pub(super) fn write(audit: &AuditLog, transaction: &Transaction<'_>, parts: i32) -> Result<(), String> {
    // As in C++, the format comes from the transaction's rule set.
    let msg = if transaction.rules.properties.audit_log.format == AuditLogFormat::JSONAuditLogFormat {
        transaction.to_json(parts)
    } else {
        let boundary = generate_boundary();
        transaction.to_old_audit_log_format(parts, &format!("-{}--", boundary), &audit.prefix)
    };

    SharedFiles::get_instance().write(&audit.path1, &msg)
}

pub(super) fn close(audit: &AuditLog) {
    SharedFiles::get_instance().close(&audit.path1);
}
