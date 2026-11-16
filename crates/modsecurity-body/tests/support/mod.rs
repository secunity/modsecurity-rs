//! A [`Recorder`] to run the multipart parser alone: it is the parser's
//! context, and keeps everything the parser tells it (variables, debug
//! log lines, temporary files) as lines of text.

#![allow(dead_code)]

use std::cell::RefCell;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use modsecurity_body::multipart::Uploads;
use modsecurity_compat::chars::to_hex_if_needed;

/// What the parser reported, in order.
pub struct Recorder<File> {
    pub events: RefCell<Vec<String>>,
    pub uploads: Uploads,
    /// Where the temporary files go (a directory of this recorder only).
    pub dir: PathBuf,
    pub files: Vec<Arc<File>>,
}

static NEXT_DIR: AtomicUsize = AtomicUsize::new(0);

impl<File> Recorder<File> {
    pub fn new(uploads: Uploads) -> Self {
        let n = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("multipart-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temporary directory");
        Recorder { events: RefCell::default(), uploads, dir, files: Vec::new() }
    }

    pub fn push(&self, event: String) {
        self.events.borrow_mut().push(event);
    }

    /// The events as text, with the random names of the temporary files
    /// replaced by `<tmp>`.
    pub fn text(&self) -> String {
        let prefix = format!("{}/upload-file-", self.dir.display());
        let mut out = String::new();
        for event in self.events.borrow().iter() {
            let mut rest = event.as_str();
            while let Some(at) = rest.find(&prefix) {
                out.push_str(&rest[..at]);
                out.push_str("<tmp>");
                // mkstemp's six characters.
                rest = &rest[(at + prefix.len() + 6).min(rest.len())..];
            }
            out.push_str(rest);
            out.push('\n');
        }
        out
    }
}

impl<File> Drop for Recorder<File> {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

pub fn show(bytes: &[u8]) -> String {
    to_hex_if_needed(bytes, true)
}

/// Makes `Recorder` the context of the parser in module `$m`, and defines
/// `$trace`: everything the parser of that module does for a body.
macro_rules! recorder_for {
    ($m:ident, $trace:ident) => {
        impl modsecurity_types::DebugSink for $crate::support::Recorder<$m::MultipartPartTmpFile> {
            fn debug_enabled(&self, level: i32) -> bool {
                level <= 9
            }

            fn debug(&self, level: i32, message: &str) {
                self.push(format!("debug[{level}] {message}"));
            }
        }

        impl $m::Context for $crate::support::Recorder<$m::MultipartPartTmpFile> {
            fn offset(&self) -> usize {
                1000
            }

            fn set(&mut self, flag: $m::Flag, value: &[u8], offset: usize) {
                self.push(format!("set {flag:?} = {} @{offset}", $crate::support::show(value)));
            }

            fn set_with_len(&mut self, flag: $m::Flag, value: &[u8], offset: usize, len: usize) {
                self.push(format!("set {flag:?} = {} @{offset}+{len}", $crate::support::show(value)));
            }

            fn add(&mut self, entries: $m::Entries, key: &[u8], value: &[u8], offset: usize) {
                self.push(format!(
                    "add {entries:?} {} = {} @{offset}",
                    $crate::support::show(key),
                    $crate::support::show(value)
                ));
            }

            fn add_with_len(&mut self, entries: $m::Entries, key: &[u8], value: &[u8], offset: usize, len: usize) {
                self.push(format!(
                    "add {entries:?} {} = {} @{offset}+{len}",
                    $crate::support::show(key),
                    $crate::support::show(value)
                ));
            }

            fn uploads(&self) -> $m::Uploads {
                let u = self.uploads;
                $m::Uploads {
                    keep_files: u.keep_files,
                    tmp_save_files: u.tmp_save_files,
                    file_limit: u.file_limit,
                    file_mode: u.file_mode,
                }
            }

            fn upload_file_prefix(&self) -> String {
                format!("{}/upload", self.dir.display())
            }

            fn keep_tmp_file(&mut self, file: std::sync::Arc<$m::MultipartPartTmpFile>) {
                self.push(format!("keep_tmp_file {}", file.filename()));
                self.files.push(file);
            }
        }

        /// What the parser does for `body` under the Content-Type `header`,
        /// given in pieces of `piece` bytes: its calls of the context, its
        /// results, and the temporary files it leaves.
        pub fn $trace(
            header: &[u8],
            body: &[u8],
            piece: usize,
            uploads: modsecurity_body::multipart::Uploads,
        ) -> String {
            let mut cx = $crate::support::Recorder::<$m::MultipartPartTmpFile>::new(uploads);
            let mut parser = $m::Multipart::new(header);
            let ok = parser.init(&mut cx);
            cx.push(format!("init -> {ok}"));
            if ok {
                for chunk in body.chunks(piece.max(1)) {
                    let ok = parser.process(&mut cx, chunk, 2000);
                    if !ok {
                        cx.push("process -> false".to_string());
                        break;
                    }
                }
            }
            let ok = parser.multipart_complete(&mut cx);
            cx.push(format!("complete -> {ok}"));
            cx.push(format!("error: {:?}", parser.error()));
            cx.push(format!("no files length: {}", parser.reqbody_no_files_length));
            drop(parser);
            for file in std::mem::take(&mut cx.files) {
                match std::fs::read(file.filename()) {
                    Ok(content) => {
                        cx.push(format!("file {} holds {}", file.filename(), $crate::support::show(&content)))
                    }
                    Err(_) => cx.push(format!("file {} is missing", file.filename())),
                }
                file.release(Some(&cx));
                cx.push(format!("after release, exists: {}", std::path::Path::new(file.filename()).exists()));
            }
            cx.text()
        }
    };
}
pub(crate) use recorder_for;
