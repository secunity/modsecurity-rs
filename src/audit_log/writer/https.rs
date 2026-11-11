//! Port of `src/audit_log/writer/https.cc`, `src/audit_log/writer/https.h`.

use crate::audit_log::audit_log::AuditLog;
use crate::audit_log::writer::writer::Writer;
use crate::transaction::Transaction;
use crate::utils::https_client::HttpsClient;

/// Posts every entry, as JSON, to the URL given by `SecAuditLog`.
#[derive(Debug, Default)]
pub struct Https;

impl Https {
    pub fn new() -> Self {
        Https
    }
}

impl Writer for Https {
    fn init(&self, _audit: &AuditLog) -> Result<(), String> {
        Ok(())
    }

    fn write(&self, audit: &AuditLog, transaction: &Transaction<'_>, parts: i32) -> Result<(), String> {
        let mut http_client = HttpsClient::new();
        crate::ms_dbg_a!(transaction, 7, "Sending logs to: {}", audit.path1);

        let log = transaction.to_json(parts);
        http_client.set_request_type("application/json");
        http_client.set_request_body(&log);
        // As in C++, a failed upload is not reported.
        http_client.download(&audit.path1);
        Ok(())
    }

    fn close(&self, _audit: &AuditLog) {}
}
