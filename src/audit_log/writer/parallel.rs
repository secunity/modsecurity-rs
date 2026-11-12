//! Port of `src/audit_log/writer/parallel.cc`, `src/audit_log/writer/parallel.h`.
//!
//! The parallel writer saves every entry into its own file under
//! `SecAuditLogStorageDir`, and an index line into `SecAuditLog` /
//! `SecAuditLog2`.

use std::fs::OpenOptions;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt;

use md5::{Digest, Md5};

use crate::audit_log::audit_log::{AuditLog, AuditLogFormat};
use crate::audit_log::writer::writer::generate_boundary;
use crate::transaction::Transaction;
use crate::utils::shared_files::SharedFiles;
use crate::utils::string::string_to_hex;
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
/// These constants describe the subpaths of this structure
/// (`AuditLogFilePath`).
pub const YEAR_MONTH_DAY_DIRECTORY: i32 = 2;
pub const YEAR_MONTH_DAY_AND_TIME_DIRECTORY: i32 = 4;
pub const YEAR_MONTH_DAY_AND_TIME_FILE_NAME: i32 = 8;

/// `logFilePath`: the requested subpaths for the time `t` (local time).
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

/// Writes the index line of an entry into the shared file `path`.
fn write_index(transaction: &Transaction<'_>, path: &str, file_name: &str, log: &[u8]) -> Result<(), String> {
    // `Utils::Md5::hexdigest` (cannot fail here).
    let log_md5 = string_to_hex(&Md5::digest(log));

    let msg = transaction.to_old_audit_log_format_index(file_name, log.len() as f64, &log_md5);
    SharedFiles::get_instance().write(path, &msg)
}

pub(super) fn init(audit: &AuditLog) -> Result<(), String> {
    if !audit.path1.is_empty() {
        SharedFiles::get_instance().open(&audit.path1)?;
    }

    if !audit.path2.is_empty() {
        SharedFiles::get_instance().open(&audit.path2)?;
    }

    if !audit.storage_dir.is_empty() {
        create_dir(&audit.storage_dir, audit.get_directory_permission() as u32)?;
    }

    Ok(())
}

pub(super) fn write(audit: &AuditLog, transaction: &Transaction<'_>, parts: i32) -> Result<(), String> {
    let ts = transaction.time_stamp;
    let mut file_name = log_file_path(
        ts,
        YEAR_MONTH_DAY_DIRECTORY | YEAR_MONTH_DAY_AND_TIME_DIRECTORY | YEAR_MONTH_DAY_AND_TIME_FILE_NAME,
    );

    // As in C++, the format comes from the transaction's rule set.
    let log = if transaction.rules.properties.audit_log.format == AuditLogFormat::Json {
        transaction.to_json(parts)
    } else {
        let boundary = generate_boundary();
        transaction.to_old_audit_log_format(parts, &format!("-{}--", boundary), &audit.prefix)
    };

    let log_path = &audit.storage_dir;
    file_name = format!("{}{}-{}", log_path, file_name, transaction.id);

    if log_path.is_empty() {
        return Err("Log path is not valid.".to_string());
    }

    let dir_mode = audit.get_directory_permission() as u32;
    create_dir(&format!("{}{}", log_path, log_file_path(ts, YEAR_MONTH_DAY_DIRECTORY)), dir_mode)?;
    create_dir(
        &format!("{}{}", log_path, log_file_path(ts, YEAR_MONTH_DAY_DIRECTORY | YEAR_MONTH_DAY_AND_TIME_DIRECTORY)),
        dir_mode,
    )?;

    // open(fileName, O_CREAT | O_WRONLY | O_APPEND, filePermission)
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(audit.get_file_permission() as u32)
        .open(&file_name)
        .map_err(|e| format!("Not able to open: {}. {}", file_name, strerror(e.raw_os_error().unwrap_or(0))))?;
    // The C++ code reopens the file with an std::ofstream (append) and
    // ignores write errors.
    let _ = file.write_all(&log);
    drop(file);

    let has_path1 = !audit.path1.is_empty();
    let has_path2 = !audit.path2.is_empty();
    if has_path1 && has_path2 {
        write_index(transaction, &audit.path2, &file_name, &log)?;
    }
    if has_path1 && !has_path2 {
        write_index(transaction, &audit.path1, &file_name, &log)?;
    }
    if !has_path1 && has_path2 {
        write_index(transaction, &audit.path2, &file_name, &log)?;
    }

    Ok(())
}

pub(super) fn close(audit: &AuditLog) {
    SharedFiles::get_instance().close(&audit.path1);
    SharedFiles::get_instance().close(&audit.path2);
}
