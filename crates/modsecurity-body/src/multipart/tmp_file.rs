//! The temporary files of uploaded file parts.

use std::fs::File;
use std::io::Write;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use modsecurity_types::{ms_dbg, ms_dbg_opt};

use super::Context;

/// A temporary file holding the content of an uploaded file part. It is
/// shared between the part being built and the transaction
/// (`Transaction::multipart_part_tmp_files`), which keeps it (and the file
/// on disk) alive until the transaction is done.
#[derive(Debug)]
pub struct MultipartPartTmpFile {
    tmp_file_name: String,
    /// The open file; `None` once closed, or when the file could not be
    /// created.
    file: Mutex<Option<File>>,
    /// Whether to delete the file when the transaction is done.
    delete: AtomicBool,
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
                // The C++ code marked the descriptor as invalid (-1) here,
                // leaking it; it is closed instead.
                file = None;
            }
        }

        MultipartPartTmpFile {
            tmp_file_name: path,
            file: Mutex::new(file),
            delete: AtomicBool::new(false),
            released: AtomicBool::new(false),
        }
    }

    /// The name of the file.
    pub fn filename(&self) -> &str {
        &self.tmp_file_name
    }

    /// Marks the file for deletion when the transaction is done.
    pub fn set_delete(&self) {
        self.delete.store(true, Ordering::Relaxed);
    }

    /// Whether the file was created (successfully or not: in the latter
    /// case writing reports the failure).
    pub fn is_valid(&self) -> bool {
        !self.tmp_file_name.is_empty()
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
            Some(mut f) => matches!(f.write(data), Ok(n) if n == data.len()),
            None => false,
        }
    }

    /// Closes the file.
    pub fn close(&self) {
        if let Ok(mut f) = self.file.lock() {
            *f = None;
        }
    }

    /// Deletes the file if it was marked for deletion (as the C++ destructor
    /// does), logging the outcome to the transaction's debug log. The
    /// transaction may call this when it is done with its temporary files;
    /// otherwise the deletion happens (without the debug messages) when the
    /// last reference is dropped.
    pub fn release(&self, cx: Option<&dyn Context>) {
        if self.released.swap(true, Ordering::Relaxed) {
            return;
        }
        if self.tmp_file_name.is_empty() || !self.delete.load(Ordering::Relaxed) {
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
