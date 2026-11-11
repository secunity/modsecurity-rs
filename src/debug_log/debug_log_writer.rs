//! Port of `src/debug_log/debug_log_writer.h` /
//! `src/debug_log/debug_log_writer.cc`.

use crate::utils::shared_files::SharedFiles;

/// Thin facade over [`SharedFiles`] (a singleton in C++; stateless here).
pub struct DebugLogWriter;

impl DebugLogWriter {
    pub fn open(file_name: &str, error: &mut String) -> bool {
        SharedFiles::get_instance().open(file_name, error)
    }

    pub fn close(file_name: &str) {
        SharedFiles::get_instance().close(file_name)
    }

    pub fn write_log(file_name: &str, msg: &str) {
        let mut err = String::new();
        let mut lmsg = msg.as_bytes().to_vec();
        lmsg.push(b'\n');
        SharedFiles::get_instance().write(file_name, &lmsg, &mut err);
    }
}
