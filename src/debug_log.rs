//! The debug log (`SecDebugLog`, `SecDebugLogLevel`).
//!
//! The interface is the [`DebugLog`] trait, which connectors (and the test
//! utilities) can implement to take the messages themselves; the stock
//! implementation is [`DefaultDebugLog`]. Writing happens through `&self`
//! because one `RulesSet` (and therefore one debug log) is shared by
//! concurrent transactions.

use std::sync::Arc;

use crate::utils::shared_files::SharedFile;

pub trait DebugLog: std::any::Any + Send + Sync {
    /// Logs `msg` at `level`.
    fn write(&self, level: u8, msg: &str);

    /// Logs `msg` at `level` for the transaction `id` handling `uri`.
    fn write_ctx(&self, level: u8, id: &str, uri: &str, msg: &str);

    /// `SecDebugLogLevel`, when set.
    fn level(&self) -> Option<u8>;

    fn set_level(&mut self, level: u8);

    /// `SecDebugLog`: the log file, when set.
    fn file(&self) -> Option<&str>;

    fn set_file(&mut self, file_name: &str) -> Result<(), String>;

    /// Whether messages of `level` are logged (what the `ms_dbg` macros
    /// check before formatting a message).
    fn enabled(&self, level: u8) -> bool {
        self.level().is_some_and(|l| l >= level)
    }
}

/// The stock debug log: appends to a [`SharedFile`].
#[derive(Debug, Default)]
pub struct DefaultDebugLog {
    level: Option<u8>,
    file_name: Option<String>,
    /// The open file (`None` when `file_name` could not be opened).
    file: Option<Arc<SharedFile>>,
}

impl DefaultDebugLog {
    pub fn new() -> Self {
        Self::default()
    }

    fn append(&self, line: String) {
        // Write errors are ignored.
        if let Some(file) = &self.file {
            let _ = file.write(line.as_bytes());
        }
    }
}

impl DebugLog for DefaultDebugLog {
    fn write(&self, level: u8, msg: &str) {
        if self.enabled(level) {
            self.append(format!("[{}] {}\n", level, msg));
        }
    }

    fn write_ctx(&self, level: u8, id: &str, uri: &str, msg: &str) {
        if self.enabled(level) {
            self.append(format!("[{}] [{}] [{}] {}\n", id, uri, level, msg));
        }
    }

    fn level(&self) -> Option<u8> {
        self.level
    }

    fn set_level(&mut self, level: u8) {
        self.level = Some(level);
    }

    fn file(&self) -> Option<&str> {
        self.file_name.as_deref()
    }

    fn set_file(&mut self, file_name: &str) -> Result<(), String> {
        // The previous file is released before the new one is opened (it is
        // reopened if it is the same and nothing else holds it).
        self.file = None;
        self.file_name = Some(file_name.to_string());
        self.file = Some(SharedFile::open(file_name)?);
        Ok(())
    }
}

/// An in-memory debug log for unit tests.
#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::{Arc, Mutex};

    use super::DebugLog;
    use crate::rules_set::RulesSet;

    /// A debug log for tests: keeps every message (level 9) with its level.
    #[derive(Debug, Default)]
    pub struct CaptureLog {
        lines: Captured,
    }

    /// The messages of a [`CaptureLog`], readable after the log is given
    /// to a rule set.
    #[derive(Debug, Default, Clone)]
    pub struct Captured(Arc<Mutex<Vec<(u8, String)>>>);

    impl Captured {
        /// The messages so far.
        pub fn messages(&self) -> Vec<String> {
            self.0.lock().unwrap().iter().map(|(_, m)| m.clone()).collect()
        }

        /// The messages so far, one `[level] message` line each.
        pub fn text(&self) -> String {
            self.0.lock().unwrap().iter().map(|(level, m)| format!("[{level}] {m}\n")).collect()
        }
    }

    impl CaptureLog {
        /// The messages so far of the capture log installed in `log`.
        pub fn lines_of(log: &dyn DebugLog) -> Vec<String> {
            let any: &dyn std::any::Any = log;
            any.downcast_ref::<CaptureLog>().expect("a CaptureLog").lines.messages()
        }
    }

    /// A rule set with a capture log, and the messages of that log.
    pub fn rules_with_log() -> (RulesSet, Captured) {
        let log = CaptureLog::default();
        let captured = log.lines.clone();
        (RulesSet::with_debug_log(Box::new(log)), captured)
    }

    impl DebugLog for CaptureLog {
        fn write(&self, level: u8, msg: &str) {
            self.lines.0.lock().unwrap().push((level, msg.to_string()));
        }
        fn write_ctx(&self, level: u8, _id: &str, _uri: &str, msg: &str) {
            self.write(level, msg);
        }
        fn level(&self) -> Option<u8> {
            Some(9)
        }
        fn set_level(&mut self, _level: u8) {}
        fn file(&self) -> Option<&str> {
            None
        }
        fn set_file(&mut self, _file_name: &str) -> Result<(), String> {
            Ok(())
        }
    }
}
