//! The parallel audit log writer: saves every entry into its own file
//! under `SecAuditLogStorageDir`, and an index line into `SecAuditLog` /
//! `SecAuditLog2`.

use crate::audit_log::format;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt;

use crate::utils::md5::Md5;

use std::sync::Arc;

use crate::audit_log::writer::{Writer, generate_boundary};
use crate::audit_log::{AuditLog, AuditLogFormat, SetupError};
use crate::transaction::Transaction;
use crate::utils::shared_files::SharedFile;
use crate::utils::system::{create_dir, strerror, strftime_local};

/// Audit log file is saved into a directory structure. This directory
/// structure is based on the timestamp of the transaction creation, at
/// the exact moment that ModSecurity be aware of a particular
/// request/transaction.
/// The expect fromat is:
///
/// `[...]/YearMonthDay/YearMonthDayAndTime/YearMonthDayAndTime-RequestId`
///
/// Example:
///
/// `/20150710/20150710-1353/20150710-135353-143654723362.584244`
///
/// These constants describe the subpaths of this structure.
pub const YEAR_MONTH_DAY_DIRECTORY: i32 = 2;
pub const YEAR_MONTH_DAY_AND_TIME_DIRECTORY: i32 = 4;
pub const YEAR_MONTH_DAY_AND_TIME_FILE_NAME: i32 = 8;

/// The requested subpaths for the time `t` (local time).
pub fn log_file_path(t: i64, part: i32) -> String {
    let mut name = String::new();

    if part & YEAR_MONTH_DAY_DIRECTORY != 0 {
        name.push_str(&strftime_local(t, "/%Y%m%d"));
    }

    if part & YEAR_MONTH_DAY_AND_TIME_DIRECTORY != 0 {
        name.push_str(&strftime_local(t, "/%Y%m%d-%H%M"));
    }

    if part & YEAR_MONTH_DAY_AND_TIME_FILE_NAME != 0 {
        name.push_str(&strftime_local(t, "/%Y%m%d-%H%M%S"));
    }

    name
}

/// Writes the index line of an entry into `index`.
fn write_index(transaction: &Transaction<'_>, index: &SharedFile, file_name: &str, log: &[u8]) -> Result<(), String> {
    let log_md5 = Md5::hexdigest(log);

    let msg = format::native_index_line(transaction, file_name, log.len() as f64, &log_md5);
    index.write(&msg)
}

pub(super) fn open(audit: &AuditLog) -> Result<Writer, SetupError> {
    let open = |path: &str| (!path.is_empty()).then(|| SharedFile::open(path)).transpose();
    let log = open(&audit.path1)?;
    let log2 = open(&audit.path2)?;

    if !audit.storage_dir.is_empty() {
        create_dir(&audit.storage_dir, audit.directory_permission() as u32)
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
    parts: i32,
) -> Result<(), String> {
    let ts = transaction.time_stamp;
    let mut file_name = log_file_path(
        ts,
        YEAR_MONTH_DAY_DIRECTORY | YEAR_MONTH_DAY_AND_TIME_DIRECTORY | YEAR_MONTH_DAY_AND_TIME_FILE_NAME,
    );

    // As in C++, the format comes from the transaction's rule set.
    let log = if transaction.rules.properties.audit_log.format == Some(AuditLogFormat::Json) {
        format::json(transaction, parts)
    } else {
        let boundary = generate_boundary();
        format::native(transaction, parts, &format!("-{}--", boundary), &audit.prefix)
    };

    let log_path = &audit.storage_dir;
    file_name = format!("{}{}-{}", log_path, file_name, transaction.id);

    if log_path.is_empty() {
        return Err("Log path is not valid.".to_string());
    }

    let dir_mode = audit.directory_permission() as u32;
    // (Writing only needs to know that it failed.)
    create_dir(&format!("{}{}", log_path, log_file_path(ts, YEAR_MONTH_DAY_DIRECTORY)), dir_mode)
        .map_err(Option::unwrap_or_default)?;
    create_dir(
        &format!("{}{}", log_path, log_file_path(ts, YEAR_MONTH_DAY_DIRECTORY | YEAR_MONTH_DAY_AND_TIME_DIRECTORY)),
        dir_mode,
    )
    .map_err(Option::unwrap_or_default)?;

    // open(fileName, O_CREAT | O_WRONLY | O_APPEND, filePermission)
    let mut file =
        OpenOptions::new()
            .create(true)
            .append(true)
            .mode(audit.file_permission() as u32)
            .open(&file_name)
            .map_err(|e| format!("Not able to open: {}. {}", file_name, strerror(e.raw_os_error().unwrap_or(0))))?;
    // The C++ code reopens the file with an std::ofstream (append) and
    // ignores write errors.
    let _ = file.write_all(&log);
    drop(file);

    if let Some(index) = index {
        write_index(transaction, index, &file_name, &log)?;
    }

    Ok(())
}
