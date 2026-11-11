//! Port of `src/utils/shared_files.h` / `src/utils/shared_files.cc`.
//!
//! Process wide registry of append-mode files shared by the debug and audit
//! logs, reference counted by file name. Writes take an exclusive `fcntl`
//! lock so that several processes can share one file, as in C++.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::sync::{Mutex, OnceLock};

struct HandlerInfo {
    fp: File,
    cnt: u32,
}

pub struct SharedFiles {
    handlers: Mutex<HashMap<String, HandlerInfo>>,
}

impl SharedFiles {
    /// `getInstance`
    pub fn get_instance() -> &'static SharedFiles {
        static INSTANCE: OnceLock<SharedFiles> = OnceLock::new();
        INSTANCE.get_or_init(|| SharedFiles { handlers: Mutex::new(HashMap::new()) })
    }

    /// `open`
    pub fn open(&self, file_name: &str, error: &mut String) -> bool {
        let mut h = self.handlers.lock().unwrap_or_else(|e| e.into_inner());
        if !h.contains_key(file_name) {
            match OpenOptions::new().append(true).create(true).open(file_name) {
                Ok(fp) => {
                    h.insert(file_name.to_string(), HandlerInfo { fp, cnt: 0 });
                }
                Err(_) => {
                    *error = format!("Failed to open file: {}", file_name);
                    return false;
                }
            }
        }
        match h.get_mut(file_name) {
            Some(i) => {
                i.cnt += 1;
                true
            }
            None => {
                *error = format!("Not able to open: {}", file_name);
                false
            }
        }
    }

    /// `close`
    pub fn close(&self, file_name: &str) {
        if file_name.is_empty() {
            return;
        }
        let mut h = self.handlers.lock().unwrap_or_else(|e| e.into_inner());
        let remove = match h.get_mut(file_name) {
            None => return,
            Some(i) => {
                i.cnt = i.cnt.saturating_sub(1);
                i.cnt == 0
            }
        };
        if remove {
            h.remove(file_name);
        }
    }

    /// `write`
    pub fn write(&self, file_name: &str, msg: &[u8], error: &mut String) -> bool {
        let mut h = self.handlers.lock().unwrap_or_else(|e| e.into_inner());
        let Some(i) = h.get_mut(file_name) else {
            *error = format!("file is not open: {}", file_name);
            return false;
        };
        let fd = i.fp.as_raw_fd();
        let mut lock: libc::flock = unsafe { std::mem::zeroed() };
        lock.l_type = libc::F_WRLCK as _;
        // SAFETY: fd is a valid open descriptor and lock is initialised.
        unsafe { libc::fcntl(fd, libc::F_SETLKW, &lock) };
        let mut ret = true;
        if i.fp.write_all(msg).is_err() {
            *error = format!("failed to write: {}", file_name);
            ret = false;
        }
        let _ = i.fp.flush();
        lock.l_type = libc::F_UNLCK as _;
        // SAFETY: as above.
        unsafe { libc::fcntl(fd, libc::F_SETLKW, &lock) };
        ret
    }
}
