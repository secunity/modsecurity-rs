//! The parallel audit log writer: saves every entry into its own file
//! under `SecAuditLogStorageDir`, and an index line into `SecAuditLog` /
//! `SecAuditLog2`.

use crate::audit_log::format;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt;

use crate::utils::hash::md5_hex;

use std::sync::Arc;

use crate::audit_log::writer::{Writer, generate_boundary};
use crate::audit_log::{AuditLog, AuditLogFormat, Parts, SetupError};
use crate::transaction::Transaction;
use crate::utils::shared_files::SharedFile;
use crate::utils::system::{create_dir, strerror, strftime_local};

/// Where the entry of a transaction is stored: a directory per day, in
/// it a directory per minute, and in that a file named after the second
/// and the request id (all from the time the transaction was created):
///
/// `/20150710/20150710-1353/20150710-135353-143654723362.584244`
struct EntryPaths {
    /// `/20150710`
    day: String,
    /// `/20150710/20150710-1353`
    minute: String,
    /// `/20150710/20150710-1353/20150710-135353`: the file name up to the
    /// request id.
    second: String,
}

/// The subpaths of an entry for the time `t` (local time).
fn entry_paths(t: i64) -> EntryPaths {
    let day = strftime_local(t, "/%Y%m%d");
    let minute = format!("{day}{}", strftime_local(t, "/%Y%m%d-%H%M"));
    let second = format!("{minute}{}", strftime_local(t, "/%Y%m%d-%H%M%S"));
    EntryPaths { day, minute, second }
}

/// Writes the index line of an entry into `index`.
fn write_index(transaction: &Transaction<'_>, index: &SharedFile, file_name: &str, log: &[u8]) -> Result<(), String> {
    let log_md5 = md5_hex(log);

    let msg = format::native_index_line(transaction, file_name, log.len(), &log_md5);
    index.write(&msg)
}

pub(super) fn open(audit: &AuditLog) -> Result<Writer, SetupError> {
    let open = |path: &str| (!path.is_empty()).then(|| SharedFile::open(path)).transpose();
    let log = open(&audit.path1)?;
    let log2 = open(&audit.path2)?;

    if !audit.storage_dir.is_empty() {
        create_dir(&audit.storage_dir, audit.directory_permission())
            .map_err(|message| message.map_or(SetupError::Unreported, SetupError::Reported))?;
    }

    Ok(Writer::Parallel { log, log2 })
}

/// Saves the entry, and its index line into `index` (`SecAuditLog2`, or
/// else `SecAuditLog`).
pub(super) fn write(
    index: Option<&Arc<SharedFile>>,
    audit: &AuditLog,
    transaction: &Transaction<'_>,
    parts: Parts,
) -> Result<(), String> {
    let ts = transaction.time_stamp;
    let paths = entry_paths(ts);

    // The format comes from the transaction's rule set.
    let log = if transaction.rules.properties.audit_log.format == Some(AuditLogFormat::Json) {
        format::json(transaction, parts)
    } else {
        let boundary = generate_boundary();
        format::native(transaction, parts, &format!("-{}--", boundary), &audit.prefix)
    };

    let log_path = &audit.storage_dir;
    let file_name = format!("{}{}-{}", log_path, paths.second, transaction.id);

    if log_path.is_empty() {
        return Err("Log path is not valid.".to_string());
    }

    let dir_mode = audit.directory_permission();
    // (Writing only needs to know that it failed.)
    create_dir(&format!("{}{}", log_path, paths.day), dir_mode).map_err(Option::unwrap_or_default)?;
    create_dir(&format!("{}{}", log_path, paths.minute), dir_mode).map_err(Option::unwrap_or_default)?;

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(audit.file_permission())
        .open(&file_name)
        .map_err(|e| format!("Not able to open: {}. {}", file_name, strerror(e.raw_os_error().unwrap_or(0))))?;
    // Write errors are ignored.
    let _ = file.write_all(&log);
    drop(file);

    if let Some(index) = index {
        write_index(transaction, index, &file_name, &log)?;
    }

    Ok(())
}
