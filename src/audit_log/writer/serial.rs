//! The serial audit log writer: appends every entry to the single file
//! `SecAuditLog` (`path1`).

use crate::audit_log::format;
use std::sync::Arc;

use crate::audit_log::writer::{Writer, generate_boundary};
use crate::audit_log::{AuditLog, AuditLogFormat, Parts, SetupError};
use crate::transaction::Transaction;
use crate::utils::shared_files::SharedFile;

pub(super) fn open(audit: &AuditLog) -> Result<Writer, SetupError> {
    Ok(Writer::Serial { log: SharedFile::open(&audit.path1)? })
}

pub(super) fn write(
    log: &Arc<SharedFile>,
    audit: &AuditLog,
    transaction: &Transaction<'_>,
    parts: Parts,
) -> Result<(), String> {
    // As in C++, the format comes from the transaction's rule set.
    let msg = if transaction.rules.properties.audit_log.format == Some(AuditLogFormat::Json) {
        format::json(transaction, parts)
    } else {
        let boundary = generate_boundary();
        format::native(transaction, parts, &format!("-{}--", boundary), &audit.prefix)
    };

    log.write(&msg)
}
