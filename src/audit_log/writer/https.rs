//! Port of `src/audit_log/writer/https.cc`, `src/audit_log/writer/https.h`.
//!
//! The HTTPS writer posts every entry, as JSON, to the URL given by
//! `SecAuditLog`.

use crate::audit_log::audit_log::AuditLog;
use crate::transaction::Transaction;
use crate::utils::https_client::HttpsClient;

pub(super) fn write(audit: &AuditLog, transaction: &Transaction<'_>, parts: i32) -> Result<(), String> {
    let mut http_client = HttpsClient::new();
    crate::ms_dbg_a!(transaction, 7, "Sending logs to: {}", audit.path1);

    let log = transaction.to_json(parts);
    http_client.set_request_type("application/json");
    http_client.set_request_body(&log);
    // As in C++, a failed upload is not reported.
    http_client.download(&audit.path1);
    Ok(())
}
