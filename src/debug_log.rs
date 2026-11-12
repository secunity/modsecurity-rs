//! Port of `headers/modsecurity/debug_log.h` and `src/debug_log/debug_log.cc`.
//!
//! The C++ `DebugLog` class is a concrete base with virtual methods that
//! connectors (and the test utilities) override. Here the interface is the
//! [`DebugLog`] trait and the stock implementation is [`DefaultDebugLog`].
//! Writing happens through `&self` because one `RulesSet` (and therefore
//! one debug log) is shared by concurrent transactions.

use crate::utils::shared_files::SharedFiles;

pub trait DebugLog: std::any::Any + Send + Sync {
    /// Logs `msg` at `level`.
    fn write(&self, level: i32, msg: &str);

    /// Logs `msg` at `level` for the transaction `id` handling `uri`.
    fn write_ctx(&self, level: i32, id: &str, uri: &str, msg: &str);

    /// `SecDebugLogLevel`, when set.
    fn level(&self) -> Option<i32>;

    fn set_level(&mut self, level: i32);

    /// `SecDebugLog`: the log file, when set.
    fn file(&self) -> Option<&str>;

    fn set_file(&mut self, file_name: &str) -> Result<(), String>;

    /// Whether messages of `level` are logged (what the `ms_dbg` macros
    /// check before formatting a message).
    fn enabled(&self, level: i32) -> bool {
        self.level().is_some_and(|l| l >= level)
    }
}

/// The stock debug log: appends to a file shared through [`SharedFiles`]
/// (C++ `DebugLogWriter`).
#[derive(Debug, Default)]
pub struct DefaultDebugLog {
    level: Option<i32>,
    file_name: Option<String>,
}

impl DefaultDebugLog {
    pub fn new() -> Self {
        Self::default()
    }

    fn append(&self, line: String) {
        // Write errors are ignored, as in C++.
        let _ = SharedFiles::instance().write(self.file_name.as_deref().unwrap_or(""), line.as_bytes());
    }
}

impl Drop for DefaultDebugLog {
    fn drop(&mut self) {
        SharedFiles::instance().close(self.file_name.as_deref().unwrap_or(""));
    }
}

impl DebugLog for DefaultDebugLog {
    fn write(&self, level: i32, msg: &str) {
        if self.enabled(level) {
            self.append(format!("[{}] {}\n", level, msg));
        }
    }

    fn write_ctx(&self, level: i32, id: &str, uri: &str, msg: &str) {
        if self.enabled(level) {
            self.append(format!("[{}] [{}] [{}] {}\n", id, uri, level, msg));
        }
    }

    fn level(&self) -> Option<i32> {
        self.level
    }

    fn set_level(&mut self, level: i32) {
        self.level = Some(level);
    }

    fn file(&self) -> Option<&str> {
        self.file_name.as_deref()
    }

    fn set_file(&mut self, file_name: &str) -> Result<(), String> {
        if let Some(old) = &self.file_name {
            SharedFiles::instance().close(old);
        }
        self.file_name = Some(file_name.to_string());
        SharedFiles::instance().open(file_name)
    }
}

/// An in-memory debug log for unit tests.
#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::Mutex;

    use super::DebugLog;

    /// Keeps every message (level 9).
    #[derive(Debug, Default)]
    pub struct CaptureLog {
        pub lines: Mutex<Vec<String>>,
    }

    impl CaptureLog {
        /// The capture log installed in `log`, with the messages so far.
        pub fn lines_of(log: &dyn DebugLog) -> Vec<String> {
            let any: &dyn std::any::Any = log;
            any.downcast_ref::<CaptureLog>().expect("a CaptureLog").lines.lock().unwrap().clone()
        }
    }

    impl DebugLog for CaptureLog {
        fn write(&self, _level: i32, msg: &str) {
            self.lines.lock().unwrap().push(msg.to_string());
        }
        fn write_ctx(&self, _level: i32, _id: &str, _uri: &str, msg: &str) {
            self.lines.lock().unwrap().push(msg.to_string());
        }
        fn level(&self) -> Option<i32> {
            Some(9)
        }
        fn set_level(&mut self, _level: i32) {}
        fn file(&self) -> Option<&str> {
            None
        }
        fn set_file(&mut self, _file_name: &str) -> Result<(), String> {
            Ok(())
        }
    }
}
