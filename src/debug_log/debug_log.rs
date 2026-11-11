//! Port of `headers/modsecurity/debug_log.h` and `src/debug_log/debug_log.cc`.
//!
//! The C++ `DebugLog` class is a concrete base with virtual methods that
//! connectors (and the test utilities) override. Here the interface is the
//! [`DebugLog`] trait and the stock implementation is [`DefaultDebugLog`].
//! Writing happens through `&self` because one `RulesSet` (and therefore
//! one debug log) is shared by concurrent transactions.

use crate::debug_log::debug_log_writer::DebugLogWriter;

pub trait DebugLog: Send + Sync {
    /// `write(level, msg)`
    fn write(&self, level: i32, msg: &str);

    /// `write(level, id, uri, msg)`
    fn write_ctx(&self, level: i32, id: &str, uri: &str, msg: &str);

    fn is_log_file_set(&self) -> bool;

    fn is_log_level_set(&self) -> bool;

    fn set_debug_log_level(&mut self, level: i32);

    fn set_debug_log_file(&mut self, file_name: &str, error: &mut String);

    fn get_debug_log_file(&self) -> &str;

    fn get_debug_log_level(&self) -> i32;

    /// The raw `m_debugLevel` member (-1 when not set), which is what the
    /// `ms_dbg` macros compare against.
    fn debug_level(&self) -> i32;

    /// Access to the concrete type (e.g. for test utilities that read back
    /// what was logged).
    fn as_any(&self) -> &dyn std::any::Any;
}

/// The stock debug log: writes to a file shared through
/// [`DebugLogWriter`].
#[derive(Debug)]
pub struct DefaultDebugLog {
    pub debug_level: i32,
    file_name: String,
}

impl Default for DefaultDebugLog {
    fn default() -> Self {
        DefaultDebugLog { debug_level: -1, file_name: String::new() }
    }
}

impl DefaultDebugLog {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Drop for DefaultDebugLog {
    fn drop(&mut self) {
        DebugLogWriter::close(&self.file_name);
    }
}

impl DebugLog for DefaultDebugLog {
    fn write(&self, level: i32, msg: &str) {
        if level <= self.debug_level {
            let msgf = format!("[{}] {}", level, msg);
            DebugLogWriter::write_log(&self.file_name, &msgf);
        }
    }

    fn write_ctx(&self, level: i32, id: &str, uri: &str, msg: &str) {
        if level <= self.debug_level {
            let msgf = format!("[{}] [{}] [{}] {}", id, uri, level, msg);
            DebugLogWriter::write_log(&self.file_name, &msgf);
        }
    }

    fn is_log_file_set(&self) -> bool {
        !self.file_name.is_empty()
    }

    fn is_log_level_set(&self) -> bool {
        self.debug_level != -1
    }

    fn set_debug_log_level(&mut self, level: i32) {
        self.debug_level = level;
    }

    fn set_debug_log_file(&mut self, file_name: &str, error: &mut String) {
        if self.is_log_file_set() {
            DebugLogWriter::close(&self.file_name);
        }
        self.file_name = file_name.to_string();
        DebugLogWriter::open(&self.file_name, error);
    }

    fn get_debug_log_file(&self) -> &str {
        &self.file_name
    }

    fn get_debug_log_level(&self) -> i32 {
        if self.debug_level < 0 { 0 } else { self.debug_level }
    }

    fn debug_level(&self) -> i32 {
        self.debug_level
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
