//! Append-mode files shared by the debug and audit logs.
//!
//! A [`SharedFile`] is opened by path; the logs of this process that open
//! the same path share it (one descriptor, one mutex), and it is closed when
//! the last of them drops its handle. Writes take an exclusive `fcntl` lock
//! too, so that several processes can share one file (`flock(2)`
//! would not do: its locks are shared by the processes that inherited the
//! descriptor, e.g. nginx workers; and `fcntl` locks do not exclude the
//! threads of one process, hence the shared mutex).

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, Weak};

use rustix::fs::{FlockOperation, fcntl_lock};

/// A file open for appending, shared by the handles to it.
#[derive(Debug)]
pub struct SharedFile {
    name: String,
    file: Mutex<File>,
}

/// The files open in this process, by path. Entries are weak: a file is
/// closed with its last handle.
fn registry() -> MutexGuard<'static, HashMap<String, Weak<SharedFile>>> {
    static FILES: OnceLock<Mutex<HashMap<String, Weak<SharedFile>>>> = OnceLock::new();
    FILES.get_or_init(Default::default).lock().unwrap_or_else(|e| e.into_inner())
}

/// An exclusive `fcntl` lock on a whole file, released on drop. Errors
/// are ignored.
struct FileLock<'f>(&'f File);

impl<'f> FileLock<'f> {
    fn exclusive(file: &'f File) -> Self {
        let _ = fcntl_lock(file, FlockOperation::LockExclusive);
        FileLock(file)
    }
}

impl Drop for FileLock<'_> {
    fn drop(&mut self) {
        let _ = fcntl_lock(self.0, FlockOperation::Unlock);
    }
}

impl SharedFile {
    /// Opens `name` for appending (creating it), or returns the handle the
    /// process already has to it.
    pub fn open(name: &str) -> Result<Arc<SharedFile>, String> {
        let mut files = registry();
        if let Some(file) = files.get(name).and_then(Weak::upgrade) {
            return Ok(file);
        }
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(name)
            .map_err(|_| format!("Failed to open file: {}", name))?;
        let file = Arc::new(SharedFile { name: name.to_string(), file: Mutex::new(file) });
        files.insert(name.to_string(), Arc::downgrade(&file));
        Ok(file)
    }

    /// Appends `msg`.
    pub fn write(&self, msg: &[u8]) -> Result<(), String> {
        // Threads of this process are serialised by the mutex, processes by
        // the fcntl lock.
        let file = self.file.lock().unwrap_or_else(|e| e.into_inner());
        let _lock = FileLock::exclusive(&file);
        let ret = (&*file).write_all(msg).map_err(|_| format!("failed to write: {}", self.name));
        let _ = (&*file).flush();
        ret
    }

    /// Whether the process has `name` open (for the tests).
    #[cfg(test)]
    pub(crate) fn is_open(name: &str) -> bool {
        registry().get(name).is_some_and(|w| w.strong_count() > 0)
    }
}

impl Drop for SharedFile {
    fn drop(&mut self) {
        // The last handle: forget the file, unless the path was opened again
        // meanwhile (its entry then refers to the new file).
        let mut files = registry();
        if files.get(&self.name).is_some_and(|w| std::ptr::eq(w.as_ptr(), self)) {
            files.remove(&self.name);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_while_a_handle_lives() {
        let dir = std::env::temp_dir().join(format!("msrs-shared-files-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("log.txt");
        let name = path.to_str().unwrap();

        let a = SharedFile::open(name).unwrap();
        let b = SharedFile::open(name).unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        a.write(b"a").unwrap();
        drop(a);
        // Still open: one handle left.
        assert!(SharedFile::is_open(name));
        b.write(b"b").unwrap();
        drop(b);
        assert!(!SharedFile::is_open(name));
        assert_eq!(std::fs::read(&path).unwrap(), b"ab");

        let missing = dir.join("no/such/dir.txt");
        let missing = missing.to_str().unwrap();
        assert_eq!(SharedFile::open(missing).unwrap_err(), format!("Failed to open file: {}", missing));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
