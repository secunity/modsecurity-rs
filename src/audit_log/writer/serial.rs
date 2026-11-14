//! The serial audit log writer: appends every entry to the single file
//! `SecAuditLog` (`path1`).

use std::sync::Arc;

use crate::audit_log::writer::{Writer, generate_boundary};
use crate::audit_log::{AuditLog, AuditLogFormat};
use crate::transaction::Transaction;
use crate::utils::shared_files::SharedFile;

pub(super) fn open(audit: &AuditLog) -> Result<Writer, String> {
    Ok(Writer::Serial { log: SharedFile::open(&audit.path1)? })
}

pub(super) fn write(
    log: &Arc<SharedFile>,
    audit: &AuditLog,
    transaction: &Transaction<'_>,
    parts: i32,
) -> Result<(), String> {
    // As in C++, the format comes from the transaction's rule set.
    let msg = if transaction.rules.properties.audit_log.format == Some(AuditLogFormat::Json) {
        transaction.to_json(parts)
    } else {
        let boundary = generate_boundary();
        transaction.to_old_audit_log_format(parts, &format!("-{}--", boundary), &audit.prefix)
    };

    log.write(&msg)
}
