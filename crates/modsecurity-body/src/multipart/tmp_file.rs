//! The temporary files of uploaded file parts.

use std::fs::File;
use std::io::Write;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use modsecurity_types::{ms_dbg, ms_dbg_opt};

use super::Context;

/// A temporary file holding the content of an uploaded file part. It is
/// shared between the part being built and the transaction
/// ([`Context::keep_tmp_file`]), which keeps it (and the file on disk)
/// alive until the transaction is done.
#[derive(Debug)]
pub struct MultipartPartTmpFile {
    tmp_file_name: String,
    /// The open file; `None` once closed, or when the file could not be
    /// created.
    file: Mutex<Option<File>>,
    /// Whether the file was created: there is one to delete.
    created: bool,
    /// Whether the file stays on disk when the transaction is done
    /// (`SecUploadKeepFiles`). It does not unless this is asked for, so
    /// that a file nobody decided about (an upload that was cut short) is
    /// not left behind.
    keep: AtomicBool,
    /// Set once the deletion was handled through
    /// [`MultipartPartTmpFile::release`].
    released: AtomicBool,
}

impl MultipartPartTmpFile {
    /// Creates and opens the file in `SecUploadDir`, named after the current
    /// time and the transaction id ([`Context::upload_file_prefix`]).
    pub(super) fn open(cx: &dyn Context) -> Self {
        let mut path = cx.upload_file_prefix();
        path.push_str("-file-XXXXXX");

        let (path, mut file) = modsecurity_native::posix::mkstemp(&path);
        ms_dbg!(cx, 4, "MultipartPartTmpFile: Create filename= {}", path);

        let mode = cx.uploads().file_mode;
        if mode != 0
            && let Some(f) = &file
        {
            use std::os::unix::fs::PermissionsExt;
            if f.set_permissions(std::fs::Permissions::from_mode(mode)).is_err() {
                // The file is closed and counts as not opened: writing to
                // it fails.
                file = None;
            }
        }

        MultipartPartTmpFile {
            tmp_file_name: path,
            created: file.is_some(),
            file: Mutex::new(file),
            keep: AtomicBool::new(false),
            released: AtomicBool::new(false),
        }
    }

    /// The name of the file.
    pub fn filename(&self) -> &str {
        &self.tmp_file_name
    }

    /// Leaves the file on disk when the transaction is done.
    pub(super) fn keep(&self) {
        self.keep.store(true, Ordering::Relaxed);
    }

    pub(super) fn is_open(&self) -> bool {
        self.file.lock().map(|f| f.is_some()).unwrap_or(false)
    }

    /// Appends `data` to the file; `false` unless all of it was written.
    pub(super) fn write(&self, data: &[u8]) -> bool {
        let Ok(guard) = self.file.lock() else {
            return false;
        };
        match guard.as_ref() {
            Some(mut f) => f.write_all(data).is_ok(),
            None => false,
        }
    }

    /// Closes the file.
    pub(super) fn close(&self) {
        if let Ok(mut f) = self.file.lock() {
            *f = None;
        }
    }

    /// Deletes the file unless it is to be kept, logging the outcome to the
    /// transaction's debug log. The transaction may call this when it is
    /// done with its temporary files; otherwise the deletion happens
    /// (without the debug messages) when the last reference is dropped.
    pub fn release(&self, cx: Option<&dyn Context>) {
        if self.released.swap(true, Ordering::Relaxed) {
            return;
        }
        if !self.created || self.keep.load(Ordering::Relaxed) {
            return;
        }
        // make sure it is closed first
        self.close();

        match std::fs::remove_file(&self.tmp_file_name) {
            Err(e) => {
                let errno = e.raw_os_error().unwrap_or(0);
                ms_dbg_opt!(
                    cx,
                    1,
                    "Multipart: Failed to delete file (part) \"{}\" because {}({})",
                    self.tmp_file_name,
                    errno,
                    modsecurity_compat::errno::strerror(errno)
                );
            }
            Ok(()) => {
                ms_dbg_opt!(cx, 4, "Multipart: file deleted successfully (part) \"{}\"", self.tmp_file_name);
            }
        }
    }
}

impl Drop for MultipartPartTmpFile {
    fn drop(&mut self) {
        self.release(None);
    }
}
