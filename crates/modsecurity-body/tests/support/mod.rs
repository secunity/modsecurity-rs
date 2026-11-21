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
    /// Temporary files cannot be created (their directory is missing).
    pub broken: bool,
    pub files: Vec<Arc<File>>,
}

static NEXT_DIR: AtomicUsize = AtomicUsize::new(0);

impl<File> Recorder<File> {
    pub fn new(uploads: Uploads) -> Self {
        let n = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("multipart-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temporary directory");
        Recorder { events: RefCell::default(), uploads, dir, broken: false, files: Vec::new() }
    }

    pub fn push(&self, event: String) {
        self.events.borrow_mut().push(event);
    }

    /// The events as text, with the names of the temporary files replaced
    /// by `<tmp>` (`<no tmp>` for those that cannot be created): they are
    /// random, in a directory of this recorder.
    pub fn text(&self) -> String {
        let dir = self.dir.display().to_string();
        let names = [(format!("{dir}/upload-file-"), "<tmp>"), (format!("{dir}/missing/upload-file-"), "<no tmp>")];
        let mut out = String::new();
        for event in self.events.borrow().iter() {
            let mut event = event.clone();
            for (prefix, shown) in &names {
                while let Some(at) = event.find(prefix.as_str()) {
                    // mkstemp's six characters.
                    let end = (at + prefix.len() + 6).min(event.len());
                    event.replace_range(at..end, shown);
                }
            }
            out.push_str(&event);
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
            fn debug_enabled(&self, level: u8) -> bool {
                level <= 9
            }

            fn debug(&self, level: u8, message: &str) {
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
                let missing = if self.broken { "/missing" } else { "" };
                format!("{}{missing}/upload", self.dir.display())
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
            broken: bool,
        ) -> String {
            let mut cx = $crate::support::Recorder::<$m::MultipartPartTmpFile>::new(uploads);
            cx.broken = broken;
            let mut parser = $m::Multipart::new(header);
            let ok = parser.init(&mut cx);
            cx.push(format!("init -> {ok}"));
            if ok {
                // The body starts at 2000; each piece is given with its
                // own offset.
                for (n, chunk) in body.chunks(piece.max(1)).enumerate() {
                    let ok = parser.process(&mut cx, chunk, 2000 + n * piece.max(1));
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

const CT: &[u8] = b"multipart/form-data; boundary=XyZ";

fn save() -> Uploads {
    Uploads { tmp_save_files: Some(true), ..Uploads::default() }
}

/// (name, Content-Type, body, upload settings). With the name `broken
/// upload directory`, temporary files cannot be created.
pub fn cases() -> Vec<(&'static str, Vec<u8>, Vec<u8>, Uploads)> {
    let none = Uploads::default();
    let b = |s: &str| s.replace('\n', "\r\n").into_bytes();
    let lf = |s: &str| s.as_bytes().to_vec();
    let mut cases: Vec<(&'static str, Vec<u8>, Vec<u8>, Uploads)> = vec![
        (
            "two fields",
            CT.to_vec(),
            b(
                "--XyZ\nContent-Disposition: form-data; name=\"a\"\n\none\n--XyZ\nContent-Disposition: form-data; name=\"b\"\n\ntwo\nlines\n--XyZ--\n",
            ),
            none,
        ),
        (
            "a file, not saved",
            CT.to_vec(),
            b(
                "--XyZ\nContent-Disposition: form-data; name=\"f\"; filename=\"x.txt\"\nContent-Type: text/plain\n\nfile body\nsecond line\n--XyZ--\n",
            ),
            none,
        ),
        (
            "a file, saved",
            CT.to_vec(),
            b(
                "--XyZ\nContent-Disposition: form-data; name=\"f\"; filename=\"x.txt\"\nContent-Type: text/plain\n\nfile body\nsecond line\n--XyZ\nContent-Disposition: form-data; name=\"a\"\n\n1\n--XyZ--\n",
            ),
            save(),
        ),
        (
            "a file, kept",
            CT.to_vec(),
            b("--XyZ\nContent-Disposition: form-data; name=\"f\"; filename=\"x.txt\"\n\nkept\n--XyZ--\n"),
            Uploads { keep_files: Some(true), file_mode: 0o600, ..none },
        ),
        (
            "file limit",
            CT.to_vec(),
            b(
                "--XyZ\nContent-Disposition: form-data; name=\"f1\"; filename=\"1\"\n\none\n--XyZ\nContent-Disposition: form-data; name=\"f2\"; filename=\"2\"\n\ntwo\n--XyZ\nContent-Disposition: form-data; name=\"f3\"; filename=\"3\"\n\nthree\n--XyZ--\n",
            ),
            Uploads { file_limit: 1, ..save() },
        ),
        (
            "filename star",
            CT.to_vec(),
            b(
                "--XyZ\nContent-Disposition: form-data; name=\"f\"; filename=\"plain.txt\"; filename*=UTF-8'en'na%C3%AFve%20file.txt\n\nx\n--XyZ--\n",
            ),
            none,
        ),
        (
            "filename star errors",
            CT.to_vec(),
            b(
                "--XyZ\nContent-Disposition: form-data; name=\"a\"; filename*='en'x\n\n1\n--XyZ\nContent-Disposition: form-data; name=\"b\"; filename*=UTF-8'en\n\n2\n--XyZ\nContent-Disposition: form-data; name=\"c\"; filename*=UTF-8''a%2\n\n3\n--XyZ\nContent-Disposition: form-data; name=\"d\"; filename*=UTF-8''a b\n\n4\n--XyZ\nContent-Disposition: form-data; name=\"e\"; filename*=UTF-8''%zz\n\n5\n--XyZ--\n",
            ),
            none,
        ),
        (
            "quoting",
            CT.to_vec(),
            b(
                "--XyZ\nContent-Disposition: form-data; name='single'\n\n1\n--XyZ\nContent-Disposition: form-data; name=bare'quote\n\n2\n--XyZ\nContent-Disposition: form-data; name=\"esc\\\"aped\\\\ \\x\"\n\n3\n--XyZ\nContent-Disposition: form-data; name=\"open\n\n4\n--XyZ\nContent-Disposition: form-data; name=\"a\" x\n\n5\n--XyZ\nContent-Disposition: form-data; name=\"a\"\"\n\n6\n--XyZ--\n",
            ),
            none,
        ),
        (
            "content-disposition errors",
            CT.to_vec(),
            b(
                "--XyZ\nContent-Disposition: attachment; name=\"a\"\n\n1\n--XyZ\nContent-Disposition: form-data name=\"a\"\n\n2\n--XyZ\nContent-Disposition: form-data; \n\n3\n--XyZ\nContent-Disposition: form-data; name\n\n4\n--XyZ\nContent-Disposition: form-data; name \n\n5\n--XyZ\nContent-Disposition: form-data; name x\n\n6\n--XyZ\nContent-Disposition: form-data; name= \n\n7\n--XyZ\nContent-Disposition: form-data; name=\"\n\n8\n--XyZ\nContent-Disposition: form-data; name=\"a\\\n\n9\n--XyZ\nContent-Disposition: form-data; other=\"a\"\n\n10\n--XyZ\nContent-Disposition: form-data; name=\"a\"; name=\"b\"\n\n11\n--XyZ\nContent-Disposition: form-data; name=\"a\"; filename=\"b\"; filename=\"c\"\n\n12\n--XyZ\nContent-Disposition: form-data; name=\"a\"; filename*=u''b; filename*=u''c\n\n13\n--XyZ\nContent-Disposition: form-data\n\n14\n--XyZ\nContent-Disposition: form-data; filename=\"only\"\n\n15\n--XyZ--\n",
            ),
            none,
        ),
        (
            "part header errors",
            CT.to_vec(),
            b(
                "--XyZ\nno colon here\nContent-Disposition: form-data; name=\"a\"\n\n1\n--XyZ\n: no name\nContent-Disposition: form-data; name=\"b\"\n\n2\n--XyZ\nBad Name: x\nContent-Disposition: form-data; name=\"c\"\n\n3\n--XyZ\nContent-Disposition: form-data; name=\"d\"\nContent-Disposition: form-data; name=\"e\"\n\n4\n--XyZ\nX-Other: 1\n\n5\n--XyZ\n folded first\nContent-Disposition: form-data; name=\"f\"\n\n6\n--XyZ--\n",
            ),
            none,
        ),
        (
            "header folding",
            CT.to_vec(),
            b(
                "--XyZ\nContent-Disposition: form-data;\n name=\"a\"\nX-Long: one\n\ttwo\n \t three\n\n1\n--XyZ\nContent-Disposition: form-data;\n\x0b name=\"b\"\n\n2\n--XyZ--\n",
            ),
            none,
        ),
        (
            "lf lines",
            CT.to_vec(),
            lf(
                "--XyZ\nContent-Disposition: form-data; name=\"a\"\n\none\n--XyZ\nContent-Disposition: form-data; name=\"b\"\n\ntwo\n--XyZ--\n",
            ),
            none,
        ),
        (
            "mixed line endings",
            CT.to_vec(),
            lf(
                "--XyZ\r\nContent-Disposition: form-data; name=\"a\"\n\r\none\n--XyZ\r\nContent-Disposition: form-data; name=\"b\"\r\n\r\ntwo\r\n--XyZ--",
            ),
            none,
        ),
        (
            "final boundary without line end",
            CT.to_vec(),
            lf("--XyZ\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\none\r\n--XyZ--"),
            none,
        ),
        (
            "final boundary where data should begin",
            CT.to_vec(),
            lf("--XyZ\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n--XyZ--"),
            none,
        ),
        (
            "boundary where data should begin",
            CT.to_vec(),
            b("--XyZ\nContent-Disposition: form-data; name=\"a\"\n\n--XyZ\nmore\n--XyZ--\n"),
            none,
        ),
        ("final boundary missing", CT.to_vec(), b("--XyZ\nContent-Disposition: form-data; name=\"a\"\n\none\n"), none),
        ("no boundaries", CT.to_vec(), b("just some text\nand more\n"), none),
        (
            "data before and after",
            CT.to_vec(),
            b("preamble\n--XyZ\nContent-Disposition: form-data; name=\"a\"\n\none\n--XyZ--\nepilogue\n"),
            none,
        ),
        (
            "unmatched and odd boundaries",
            CT.to_vec(),
            b(
                "--XyZ\nContent-Disposition: form-data; name=\"a\"\n\n--other\ntext --XyZ inside\n--Xy\n--XyZ\nContent-Disposition: form-data; name=\"b\"\n\n2\n--XyZ--\n",
            ),
            none,
        ),
        (
            "boundary with trailing text",
            CT.to_vec(),
            b("--XyZ\nContent-Disposition: form-data; name=\"a\"\n\n1\n--XyZtail\n"),
            none,
        ),
        (
            "boundary after whitespace",
            CT.to_vec(),
            b("-- XyZ\nContent-Disposition: form-data; name=\"a\"\n\n1\n--XyZ--\n"),
            none,
        ),
        (
            "duplicate final boundary",
            CT.to_vec(),
            lf("--XyZ\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--XyZ--\r\n--XyZ--\r\n"),
            none,
        ),
        (
            "nul bytes",
            CT.to_vec(),
            lf(
                "--XyZ\r\nContent-Disposition: form-data; name=\"a\"\r\nX-Nul: a\0b\r\n\r\nva\0lue\r\n--XyZ\r\nContent-Disposition: form-data; name=\"b\"\r\n\r\n--\0XyZ\r\n--XyZ\0\r\n--XyZ--\r\n",
            ),
            none,
        ),
        (
            "an upload cut short",
            CT.to_vec(),
            lf("--XyZ\r\nContent-Disposition: form-data; name=\"f\"; filename=\"x.txt\"\r\n\r\nfile body\r\n"),
            save(),
        ),
        (
            "an upload cut short, files kept",
            CT.to_vec(),
            lf("--XyZ\r\nContent-Disposition: form-data; name=\"f\"; filename=\"x.txt\"\r\n\r\nfile body\r\n"),
            Uploads { keep_files: Some(true), ..save() },
        ),
        (
            "quoted boundary",
            b"multipart/form-data; boundary=\"XyZ\"".to_vec(),
            b("--\"XyZ\"\nContent-Disposition: form-data; name=\"a\"\n\n1\n--XyZ--\n"),
            none,
        ),
        (
            "quoted boundary, used",
            b"multipart/form-data; boundary=\"XyZ\"".to_vec(),
            b("--XyZ\nContent-Disposition: form-data; name=\"a\"\n\n1\n--XyZ--\n"),
            none,
        ),
        (
            "boundary with a parameter after it",
            b"multipart/form-data; boundary=XyZ; charset=UTF-8".to_vec(),
            b("--XyZ\nContent-Disposition: form-data; name=\"a\"\n\n1\n--XyZ--\n"),
            none,
        ),
        (
            "empty value and empty lines",
            CT.to_vec(),
            b(
                "--XyZ\nContent-Disposition: form-data; name=\"a\"\n\n\n--XyZ\nContent-Disposition: form-data; name=\"b\"\n\n\n\n\n--XyZ--\n",
            ),
            none,
        ),
    ];

    // A value of many short lines, each a buffer of the parser.
    let lines = "1\n\n2\r\n".repeat(50);
    cases.push((
        "a value of many short lines",
        CT.to_vec(),
        lf(&format!("--XyZ\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n{lines}end\r\n--XyZ--\r\n")),
        none,
    ));

    // Lines longer than the parser's buffer: in a value, in a saved file
    // (with a carriage return at the buffer's end), and in a header.
    let long = "v".repeat(5000);
    cases.push((
        "long value",
        CT.to_vec(),
        b(&format!("--XyZ\nContent-Disposition: form-data; name=\"a\"\n\n{long}\nshort\n--XyZ--\n")),
        none,
    ));
    let mut file = b("--XyZ\nContent-Disposition: form-data; name=\"f\"; filename=\"big\"\n\n");
    file.extend(std::iter::repeat_n(b'x', 4095));
    file.extend_from_slice(b"\r\nrest\r\r\n\nend\r\n--XyZ--\r\n");
    cases.push(("long file line", CT.to_vec(), file, save()));
    cases.push((
        "long header",
        CT.to_vec(),
        b(&format!("--XyZ\nContent-Disposition: form-data; name=\"{long}\"\n\n1\n--XyZ--\n")),
        none,
    ));
    let folded = format!(" {}\n", "f".repeat(1500)).repeat(3);
    cases.push((
        "folded header too long",
        CT.to_vec(),
        b(&format!("--XyZ\nContent-Disposition: form-data; name=\"a\"\nX-Long: 1\n{folded}\n1\n--XyZ--\n")),
        none,
    ));

    // A part after long lines: its offsets depend on how the line breaks
    // around them were counted.
    let mut after = b("--XyZ\nContent-Disposition: form-data; name=\"a\"\n\nfirst\n");
    after.extend(std::iter::repeat_n(b'y', 4096));
    after.extend_from_slice(b"\r\n");
    after.extend(std::iter::repeat_n(b'z', 4095));
    after.extend_from_slice(
        b"\r\ntail\r\n--XyZ\r\nContent-Disposition: form-data; name=\"b\"\r\n\r\nsecond\r\n--XyZ--\r\n",
    );
    cases.push(("a field after long lines", CT.to_vec(), after.clone(), none));
    let after_file = String::from_utf8(after).unwrap().replace("name=\"a\"", "name=\"a\"; filename=\"f\"").into_bytes();
    cases.push(("a field after a long saved file", CT.to_vec(), after_file.clone(), save()));
    cases.push(("a field after a long file", CT.to_vec(), after_file, none));
    cases.push((
        "broken upload directory",
        CT.to_vec(),
        b("--XyZ\nContent-Disposition: form-data; name=\"f\"; filename=\"x\"\n\ndata\n--XyZ--\n"),
        save(),
    ));

    // Content-Type headers the parser refuses or flags.
    let body = b("--XyZ\nContent-Disposition: form-data; name=\"a\"\n\n1\n--XyZ--\n");
    for (name, header) in [
        ("header: empty", &b""[..]),
        ("header: other type", b"text/plain; boundary=XyZ"),
        ("header: no boundary", b"multipart/form-data"),
        ("header: upper case boundary", b"multipart/form-data; BOUNDARY=XyZ"),
        ("header: two boundaries", b"multipart/form-data; boundary=XyZ; boundary=abc"),
        ("header: no semicolon", b"multipart/form-data boundary=XyZ"),
        ("header: text before boundary", b"multipart/form-data; x boundary=XyZ"),
        ("header: no equals sign", b"multipart/form-data; boundary"),
        ("header: whitespace around the equals sign", b"multipart/form-data; boundary = XyZ"),
        ("header: text after the name", b"multipart/form-data; boundaryx=XyZ"),
        ("header: half quoted", b"multipart/form-data; boundary=\"XyZ"),
        ("header: empty quoted", b"multipart/form-data; boundary=\"\""),
        ("header: empty", b"multipart/form-data; boundary="),
        ("header: boundary in the boundary", b"multipart/form-data; boundary=aBoundary=b"),
        ("header: invalid characters", b"multipart/form-data; boundary=Xy{Z"),
        ("header: nul byte", b"multipart/form-data; boundary=XyZ\0abc"),
        ("header: mixed case type", b"MultiPart/Form-Data; boundary=XyZ"),
    ] {
        cases.push((name, header.to_vec(), body.clone(), none));
    }
    cases.push((
        "header: too long",
        format!("multipart/form-data; boundary={}", "b".repeat(1024)).into_bytes(),
        body,
        none,
    ));
    cases
}
