//! Port of `src/utils/shared_files.h` / `src/utils/shared_files.cc`.
//!
//! Process wide registry of append-mode files shared by the debug and audit
//! logs, reference counted by file name. Writes take an exclusive `fcntl`
//! lock so that several processes can share one file, as in C++ (`flock(2)`
//! would not do: its locks are shared by the processes that inherited the
//! descriptor, e.g. nginx workers).
//!
//! The registry lock is only held to look a file up; writing holds the lock
//! of that file alone, so a slow file does not block the others.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use rustix::fs::{FlockOperation, fcntl_lock};

/// A registered file and the number of `open`s not yet `close`d.
struct HandlerInfo {
    file: Arc<Mutex<File>>,
    cnt: u32,
}

pub struct SharedFiles {
    handlers: Mutex<HashMap<String, HandlerInfo>>,
}

/// An exclusive `fcntl` lock on a whole file, released on drop. Errors
/// are ignored, as in C++.
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

impl SharedFiles {
    /// `getInstance`
    pub fn instance() -> &'static SharedFiles {
        static INSTANCE: OnceLock<SharedFiles> = OnceLock::new();
        INSTANCE.get_or_init(|| SharedFiles { handlers: Mutex::new(HashMap::new()) })
    }

    fn handlers(&self) -> MutexGuard<'_, HashMap<String, HandlerInfo>> {
        self.handlers.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `open`: opens `file_name` for appending, or adds a reference to it
    /// if it is already open.
    pub fn open(&self, file_name: &str) -> Result<(), String> {
        let mut h = self.handlers();
        if let Some(i) = h.get_mut(file_name) {
            i.cnt += 1;
            return Ok(());
        }
        let fp = OpenOptions::new()
            .append(true)
            .create(true)
            .open(file_name)
            .map_err(|_| format!("Failed to open file: {}", file_name))?;
        h.insert(file_name.to_string(), HandlerInfo { file: Arc::new(Mutex::new(fp)), cnt: 1 });
        Ok(())
    }

    /// `close`: drops a reference; the file is closed with the last one.
    pub fn close(&self, file_name: &str) {
        if file_name.is_empty() {
            return;
        }
        let mut h = self.handlers();
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

    /// `write`: appends `msg` to the open file `file_name`.
    pub fn write(&self, file_name: &str, msg: &[u8]) -> Result<(), String> {
        let file = self.handlers().get(file_name).map(|i| Arc::clone(&i.file));
        let file = file.ok_or_else(|| format!("file is not open: {}", file_name))?;
        // Threads of this process are serialised by the mutex, processes by
        // the fcntl lock.
        let file = file.lock().unwrap_or_else(|e| e.into_inner());
        let _lock = FileLock::exclusive(&file);
        let ret = (&*file).write_all(msg).map_err(|_| format!("failed to write: {}", file_name));
        let _ = (&*file).flush();
        ret
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_counted_by_name() {
        let dir = std::env::temp_dir().join(format!("msrs-shared-files-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("log.txt");
        let name = path.to_str().unwrap();
        let sf = SharedFiles::instance();

        assert_eq!(sf.write(name, b"x"), Err(format!("file is not open: {}", name)));
        sf.open(name).unwrap();
        sf.open(name).unwrap();
        sf.write(name, b"a").unwrap();
        sf.close(name);
        // Still open: one reference left.
        sf.write(name, b"b").unwrap();
        sf.close(name);
        assert!(sf.write(name, b"c").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"ab");

        let missing = dir.join("no/such/dir.txt");
        let missing = missing.to_str().unwrap();
        assert_eq!(sf.open(missing), Err(format!("Failed to open file: {}", missing)));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
