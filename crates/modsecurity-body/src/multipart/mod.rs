//! The `multipart/form-data` request body processor. The parser is a line
//! oriented state machine working on an internal buffer of
//! [`MULTIPART_BUF_SIZE`] bytes: the data is accumulated until a line feed
//! (or a full buffer) and every buffer is then examined as a possible
//! boundary, part header or part data. A NUL byte is a byte like another
//! in a line; in a part header it is an error.
//!
//! The parts of the parser: the boundary from the Content-Type header
//! (`content_type`), the lines of a part (`part`), its Content-Disposition
//! header (`content_disposition`) and the temporary files of uploads
//! (`tmp_file`). This module has the state machine over the lines and what
//! is reported when the body ends.
//!
//! Form fields end up in `ARGS`/`ARGS_POST`, files in `FILES`,
//! `FILES_NAMES`, `FILES_SIZES`, `FILES_TMP_CONTENT`, `FILES_TMPNAMES`
//! and `FILES_COMBINED_SIZE`, and the anomalies found while parsing in the
//! `MULTIPART_*` flags.

use std::sync::Arc;

use modsecurity_compat::chars::is_space;
use modsecurity_types::{DebugSink, ms_dbg, ms_dbg_opt};

mod content_disposition;
mod content_type;
mod part;
mod tmp_file;

use part::{MultipartPart, PartKind, PartState};
pub use tmp_file::MultipartPartTmpFile;

/// The size of the parser's buffer: the longest line it looks at as a
/// whole.
pub const MULTIPART_BUF_SIZE: usize = 4096;

// ---------------------------------------------------------------------------
// C string helpers
// ---------------------------------------------------------------------------

/// Whether `s` has `needle` at `from` (never past its end, except for an
/// empty `needle`).
fn has_at(s: &[u8], from: usize, needle: &[u8]) -> bool {
    s[from.min(s.len())..].starts_with(needle)
}

/// The position of the first `needle` in `haystack`, as
/// `strstr(haystack, needle)` on a NUL free haystack.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

// ---------------------------------------------------------------------------
// The context
// ---------------------------------------------------------------------------

/// The single valued variables the parser sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flag {
    MultipartBoundaryQuoted,
    MultipartBoundaryWhiteSpace,
    MultipartCrlfLfLines,
    MultipartDataAfter,
    MultipartDataBefore,
    MultipartDuplicatePartHeader,
    MultipartHeaderFolding,
    MultipartInvalidHeaderFolding,
    MultipartInvalidPart,
    MultipartInvalidQuoting,
    MultipartLfLine,
    MultipartMissingSemicolon,
    MultipartStrictError,
    MultipartUnmatchedBoundary,
    FilesCombinedSize,
}

/// The multi valued variables the parser adds entries to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Entries {
    Args,
    ArgsPost,
    Files,
    FilesNames,
    FilesSizes,
    FilesTmpContent,
    FilesTmpNames,
    MultipartFileName,
    MultipartFileNameCharset,
    MultipartFileNameLanguage,
    MultipartName,
    MultipartPartHeaders,
}

/// The upload settings of the configuration.
#[derive(Debug, Clone, Copy, Default)]
pub struct Uploads {
    /// `SecUploadKeepFiles`.
    pub keep_files: Option<bool>,
    /// `SecTmpSaveUploadedFiles`.
    pub tmp_save_files: Option<bool>,
    /// `SecUploadFileLimit` (0 when not set).
    pub file_limit: u32,
    /// `SecUploadFileMode` (0 when not set).
    pub file_mode: u32,
}

/// What the multipart parser needs from the transaction it parses for: the
/// variables it reports, the upload settings and the debug log.
pub trait Context: DebugSink {
    /// The offset of the request body in the transaction (the base of the
    /// offsets of the variables).
    fn offset(&self) -> usize;

    /// Sets the variable `flag`; its origin is at `offset`.
    fn set(&mut self, flag: Flag, value: &[u8], offset: usize);

    /// [`Self::set`] with an origin of `len` bytes.
    fn set_with_len(&mut self, flag: Flag, value: &[u8], offset: usize, len: usize);

    /// Adds `key` = `value` to the variable `entries`; its origin is at
    /// `offset`.
    fn add(&mut self, entries: Entries, key: &[u8], value: &[u8], offset: usize);

    /// [`Self::add`] with an origin of `len` bytes.
    fn add_with_len(&mut self, entries: Entries, key: &[u8], value: &[u8], offset: usize, len: usize);

    /// The upload settings.
    fn uploads(&self) -> Uploads;

    /// The path of a temporary file for an uploaded part, up to its
    /// `-file-XXXXXX` suffix: the upload directory, the current time and
    /// the transaction id.
    fn upload_file_prefix(&self) -> String;

    /// Hands over a temporary file: the transaction keeps it (and decides
    /// about its deletion) until it is done.
    fn keep_tmp_file(&mut self, file: Arc<MultipartPartTmpFile>);
}

// ---------------------------------------------------------------------------
// Multipart
// ---------------------------------------------------------------------------

/// The line ending right before the current position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LineEnd {
    /// Neither a line feed nor a carriage return.
    None,
    /// A carriage return.
    Cr,
    /// A line feed alone.
    Lf,
    /// A carriage return and a line feed.
    CrLf,
}

/// What the parser found unusual (the `MULTIPART_*` variables say so to
/// the rules).
#[derive(Debug, Default)]
struct Flags {
    /// An error that ends the parsing.
    error: bool,
    data_before: bool,
    data_after: bool,
    duplicate_part_header: bool,
    header_folding: bool,
    boundary_quoted: bool,
    lf_line: bool,
    crlf_line: bool,
    /// 1: a line looks like a boundary but is not this body's. 2: the
    /// boundary of this body was found again after its first line (a
    /// value other than 0, so that rules testing `!@eq 0` still see every
    /// case, while `@eq 1` is the unmatched one alone).
    unmatched_boundary: u8,
    boundary_whitespace: bool,
    missing_semicolon: bool,
    invalid_quoting: bool,
    invalid_part: bool,
    invalid_header_folding: bool,
    file_limit_exceeded: bool,
}

/// A flag as the value of its variable.
fn bit(on: bool) -> &'static [u8] {
    if on { b"1" } else { b"0" }
}

/// The state of the multipart parser for one request body.
#[derive(Debug)]
pub struct Multipart {
    pub reqbody_no_files_length: usize,
    /// The most recent parsing error (`MULTIPART_*` failures and the
    /// upload file limit), reported as `REQBODY_ERROR_MSG`. A later error
    /// replaces an earlier one.
    error: Option<String>,
    /// The parts read so far.
    parts: Vec<MultipartPart>,

    /// How many parts were saved as files.
    nfiles: u32,

    /// The MIME boundary: where parts begin and end.
    boundary: Vec<u8>,
    /// How many boundary lines were found.
    boundary_count: usize,

    /// Set by [`Multipart::init`].
    initialized: bool,
    /// The data not yet looked at: a line being read, at most
    /// [`MULTIPART_BUF_SIZE`] bytes of it.
    buf: Vec<u8>,
    /// Whether `buf` starts where a line starts.
    buf_contains_line: bool,
    /// Where `buf` starts in the body.
    buf_offset: usize,

    line_end: LineEnd,
    /// `line_end` where the previous buffer ended.
    line_end_at_buffer_end: LineEnd,

    /// The part being read.
    mpp: Option<MultipartPart>,
    part_state: PartState,
    /// While reading the data of a part: whether there was any since the
    /// empty line after its headers.
    part_data_read: bool,

    /// The line break that ended the previous piece of data, held back:
    /// it is data if more data follows, and belongs to the boundary if a
    /// boundary does.
    reserve: &'static [u8],

    seen_data: bool,
    /// The final boundary was found.
    is_complete: bool,

    flags: Flags,

    /// The Content-Type header of the request.
    header: Vec<u8>,
    /// `SecUploadKeepFiles`, read by the cleanup.
    upload_keep_files: Option<bool>,
    /// Whether `cleanup` already ran.
    cleaned_up: bool,
}

impl Multipart {
    /// A parser for a body with the Content-Type `header`.
    pub fn new(header: &[u8]) -> Self {
        Multipart {
            reqbody_no_files_length: 0,
            error: None,
            parts: Vec::new(),
            nfiles: 0,
            boundary: Vec::new(),
            boundary_count: 0,
            initialized: false,
            buf: Vec::with_capacity(MULTIPART_BUF_SIZE),
            buf_contains_line: false,
            buf_offset: 0,
            line_end: LineEnd::None,
            line_end_at_buffer_end: LineEnd::None,
            mpp: None,
            part_state: PartState::Headers,
            part_data_read: false,
            reserve: b"",
            seen_data: false,
            is_complete: false,
            flags: Flags::default(),
            header: header.to_vec(),
            upload_keep_files: None,
            cleaned_up: false,
        }
    }

    /// Records `message` as the error of the body, and logs it at `level`.
    fn fail(&mut self, cx: &dyn Context, level: u8, message: impl Into<String>) {
        let message = message.into();
        ms_dbg!(cx, level, "{}", message);
        self.error = Some(message);
    }

    /// The error to report, if processing failed.
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// Validates the Content-Type header and extracts the boundary.
    pub fn init(&mut self, cx: &mut dyn Context) -> bool {
        self.upload_keep_files = cx.uploads().keep_files;
        self.initialized = true;
        self.buf.clear();
        self.buf_contains_line = true;
        self.mpp = None;

        match self.read_boundary(cx) {
            Ok(()) => true,
            Err(refused) => {
                if let Some(message) = refused {
                    self.flags.error = true;
                    self.fail(cx, 4, message);
                }
                false
            }
        }
    }

    /// Parses the body. Assumes that all data is in `data` (we are not
    /// processing chunks); `offset` is where the body starts.
    pub fn process(&mut self, cx: &mut dyn Context, data: &[u8], offset: usize) -> bool {
        if data.is_empty() {
            return true;
        }
        self.seen_data = true;

        if self.is_complete {
            self.flags.data_before = true;
            ms_dbg!(cx, 4, "Multipart: Ignoring data after last boundary (received {} bytes)", data.len());
            return true;
        }

        if !self.initialized {
            self.flags.error = true;
            ms_dbg!(cx, 4, "Multipart: Internal error in process_chunk: no space left in the buffer");
            return false;
        }

        // The data goes through the buffer one byte at a time; `z` counts
        // the steps.
        let mut rest = data;
        let mut z: usize = 0;
        while let Some(&c) = rest.first() {
            z += 1;

            // A carriage return is not taken as the last byte of the
            // buffer: the buffer is handled first, and the byte is looked
            // at again.
            let cr_held_back = c == b'\r' && self.buf.len() == MULTIPART_BUF_SIZE - 1;
            if !cr_held_back {
                rest = &rest[1..];
                self.buf.push(c);
            }

            // Until the end of the line or of the buffer.
            let full = self.buf.len() == MULTIPART_BUF_SIZE || cr_held_back;
            if c == b'\n' || full {
                let mut buf = std::mem::take(&mut self.buf);
                let ok = self.process_buffer(cx, &mut buf, full, offset.wrapping_add(z));
                self.buf = buf;
                if !ok {
                    return false;
                }

                // Where the data we are about to read starts: this is how
                // the offsets of the files and variables are known.
                self.buf_offset = self.buf_offset.wrapping_add(self.buf.len());

                self.buf.clear();
                self.buf_contains_line = c == b'\n';

                if c == b'\n' {
                    self.line_end = if self.line_end == LineEnd::Cr { LineEnd::CrLf } else { LineEnd::Lf };
                }
                self.line_end_at_buffer_end = self.line_end;
            }

            if c == b'\r' {
                self.line_end = LineEnd::Cr;
            } else if c != b'\n' {
                self.line_end = LineEnd::None;
            }

            if self.is_complete && !rest.is_empty() {
                self.flags.data_after = true;
                ms_dbg!(cx, 4, "Multipart: Ignoring data after last boundary ({}bytes left)", rest.len());
                return true;
            }
        }

        true
    }

    /// Handles the buffer `buf`, a line or `full` without the end of one:
    /// as a boundary, or as a header line or data of the part being read
    /// (which may cut a line break off `buf`, see
    /// [`Self::process_part_data`]). `false` on an error that ends the
    /// parsing.
    fn process_buffer(&mut self, cx: &mut dyn Context, buf: &mut Vec<u8>, full: bool, offset: usize) -> bool {
        if self.buf_contains_line {
            match self.boundary_line(cx, buf) {
                Some(true) => return true,
                Some(false) => {}
                None => return false,
            }
        }

        let Some(mut mpp) = self.mpp.take() else {
            self.flags.data_before = true;
            ms_dbg!(cx, 4, "Multipart: Ignoring data before first boundary.");
            return true;
        };
        let ok = match self.part_state {
            PartState::Headers if full => {
                // part header lines must be shorter than
                // MULTIPART_BUF_SIZE bytes
                self.flags.error = true;
                self.fail(cx, 4, format!("Multipart: Part header line over {} bytes long", MULTIPART_BUF_SIZE));
                false
            }
            PartState::Headers => {
                // A failing part header records its error but does not
                // stop the processing.
                self.process_part_header(cx, &mut mpp, buf, offset);
                true
            }
            PartState::Data => {
                let ok = self.process_part_data(cx, &mut mpp, buf, offset);
                if !ok {
                    self.flags.error = true;
                }
                ok
            }
        };
        self.mpp = Some(mpp);
        ok
    }

    /// Looks at the line `buf` as a boundary. `Some(true)`: it is one, and
    /// the part before it is finished. `Some(false)`: it is not, or it
    /// must not be one here. `None`: it is a malformed one, an error that
    /// ends the parsing.
    fn boundary_line(&mut self, cx: &mut dyn Context, buf: &[u8]) -> Option<bool> {
        let line = buf;

        // Do we have something that looks like a boundary?
        if line.len() <= 3 || !line.starts_with(b"--") {
            // We do not think so. Look into the buffer to see if there's
            // anything there that resembles a boundary.
            let resembles = |i: usize| has_at(buf, i, b"--") && has_at(buf, i + 2, &self.boundary);
            if (0..buf.len()).any(resembles) {
                self.flags.unmatched_boundary = 1;
            }
            return Some(false);
        }

        // Does it match our boundary?
        if line.len() < self.boundary.len() + 2 || !has_at(buf, 2, &self.boundary) {
            return self.unmatched_boundary_line(cx, buf, line.len());
        }

        if self.line_end_at_buffer_end == LineEnd::Lf {
            self.flags.lf_line = true;
        }
        if !self.part_data_read && self.boundary_count > 0 {
            // string matches our boundary, but it's where part data should
            // begin
            self.flags.invalid_part = true;
            ms_dbg!(cx, 3, "Multipart: Invalid part (data contains boundary)");
            return Some(false);
        }

        if self.boundary_count > 0 {
            self.flags.unmatched_boundary = 2;
        }

        // Is this the final boundary?
        let mut end = 2 + self.boundary.len();
        let is_final = has_at(buf, end, b"--");
        if is_final {
            end += 2;
            if self.is_complete {
                self.flags.error = true;
                self.fail(cx, 4, "Multipart: Invalid boundary (final duplicate).");
                return None;
            }
        }

        // Allow for CRLF and LF line endings.
        let (lf, crlf) = (&buf[end..] == b"\n", &buf[end..] == b"\r\n");
        if !lf && !crlf {
            self.flags.error = true;
            self.fail(cx, 4, format!("Multipart: Invalid boundary: {}", String::from_utf8_lossy(line)));
            return None;
        }
        if lf {
            self.flags.lf_line = true;
        } else {
            self.flags.crlf_line = true;
        }

        self.process_boundary(cx, is_final);
        if is_final {
            self.is_complete = true;
        }
        self.boundary_count += 1;
        Some(true)
    }

    /// A line of `len` characters that starts like a boundary but is not
    /// the boundary of this body: an error if it is the boundary in quotes
    /// or after whitespace.
    fn unmatched_boundary_line(&mut self, cx: &mut dyn Context, buf: &[u8], len: usize) -> Option<bool> {
        // Check if an attempt to use quotes around the boundary was made.
        if self.flags.boundary_quoted
            && len >= self.boundary.len() + 3
            && buf[2] == b'"'
            && has_at(buf, 3, &self.boundary)
        {
            self.flags.error = true;
            self.fail(cx, 4, "Multipart: Invalid boundary (quotes).");
            return None;
        }

        // Check the beginning of the boundary for whitespace.
        let mut p = 2;
        while buf.get(p).is_some_and(|&c| is_space(c)) {
            p += 1;
        }
        if p != 2 && has_at(buf, p, &self.boundary) {
            self.flags.error = true;
            self.fail(cx, 4, "Multipart: Invalid boundary (whitespace).");
            return None;
        }

        self.flags.unmatched_boundary = 1;
        Some(false)
    }

    /// Handles a boundary line: finishes the part being built, and starts a
    /// new one unless this is the last boundary.
    fn process_boundary(&mut self, cx: &mut dyn Context, last_part: bool) {
        // if there was a part being built finish it
        if let Some(mut mpp) = self.mpp.take() {
            // record all the part header lines from the part into the
            // transaction collection
            for (off, line) in &mpp.header_lines {
                cx.add(Entries::MultipartPartHeaders, &mpp.name, line, *off);
                ms_dbg!(cx, 9, "Multipart: Added part header line:{}", String::from_utf8_lossy(line));
            }

            match &mpp.kind {
                PartKind::File(file) => {
                    // close the temp file
                    if let Some(f) = &file.tmp_file
                        && f.is_valid()
                    {
                        f.close();
                    }
                }
                PartKind::Field { pieces } => {
                    // now construct a single string out of the pieces
                    for (d, off) in pieces {
                        if mpp.value_offset == 0 {
                            mpp.value_offset = *off;
                        }
                        mpp.value.extend_from_slice(d);
                    }
                }
            }

            if mpp.name.is_empty() {
                self.flags.invalid_part = true;
                ms_dbg!(
                    cx,
                    3,
                    "Multipart: Skipping invalid part (part name missing): (offset {}, length {})",
                    mpp.offset,
                    mpp.length
                );
            } else {
                // add the part to the list of parts
                if mpp.file().is_some() {
                    // filename* takes precedence over filename
                    let fname = if !mpp.filename_star.is_empty() { &mpp.filename_star } else { &mpp.filename };
                    ms_dbg!(
                        cx,
                        9,
                        "Multipart: Added file part to the list: name \"{}\" file name \"{}\" (offset {}, length {})",
                        String::from_utf8_lossy(&mpp.name),
                        String::from_utf8_lossy(fname),
                        mpp.offset,
                        mpp.length
                    );
                } else {
                    ms_dbg!(
                        cx,
                        9,
                        "Multipart: Added part to the list: name \"{}\" (offset {}, length {})",
                        String::from_utf8_lossy(&mpp.name),
                        mpp.offset,
                        mpp.length
                    );
                }
                self.parts.push(mpp);
            }
        }

        if !last_part {
            // start building a new part
            self.mpp = Some(MultipartPart::new());
            self.part_state = PartState::Headers;
            self.part_data_read = false;
            self.reserve = b"";
        }
    }

    /// Finalizes multipart processing. This method is invoked at the end,
    /// when it is clear that there is no more data to be processed.
    ///
    /// The cleanup (marking the temporary files for deletion, with its
    /// debug messages) needs the transaction, so it runs at the end of this
    /// method; dropping the parser only runs it, without the messages, when
    /// this method was not called.
    pub fn multipart_complete(&mut self, cx: &mut dyn Context) -> bool {
        let ret = self.complete(cx);
        self.cleanup(Some(cx));
        ret
    }

    fn complete(&mut self, cx: &mut dyn Context) -> bool {
        self.report_flags(cx);

        if self.seen_data && !self.is_complete {
            if self.boundary_count == 0 {
                self.fail(cx, 1, "Multipart: No boundaries found in payload.");
                return false;
            }

            // Check if we have the final boundary (that we haven't
            // processed yet) in the buffer.
            if self.buf_contains_line && self.buffer_is_final_boundary() {
                self.final_boundary_without_line_end(cx);
            }

            if !self.is_complete {
                self.fail(cx, 1, "Multipart: Final boundary missing.");
                return false;
            }
        }

        self.report_parts(cx);
        true
    }

    /// Sets the `MULTIPART_*` variables, and logs a warning for each
    /// anomaly.
    fn report_flags(&self, cx: &mut dyn Context) {
        let off = cx.offset();
        let flags = &self.flags;
        let report = |cx: &mut dyn Context, flag: Flag, on: bool, warning: &str| {
            cx.set(flag, bit(on), off);
            if on {
                ms_dbg!(cx, 4, "Multipart: Warning: {}", warning);
            }
        };

        cx.set(Flag::MultipartUnmatchedBoundary, flags.unmatched_boundary.to_string().as_bytes(), off);
        report(cx, Flag::MultipartDataBefore, flags.data_before, "seen data before first boundary.");
        report(cx, Flag::MultipartDataAfter, flags.data_after, "seen data after last boundary.");
        report(cx, Flag::MultipartDuplicatePartHeader, flags.duplicate_part_header, "seen duplicate part header.");
        report(cx, Flag::MultipartBoundaryQuoted, flags.boundary_quoted, "boundary was quoted.");
        report(cx, Flag::MultipartBoundaryWhiteSpace, flags.boundary_whitespace, "boundary whitespace in C-T header.");
        report(cx, Flag::MultipartHeaderFolding, flags.header_folding, "header folding used.");
        self.set_line_ending_flags(cx);
        report(cx, Flag::MultipartMissingSemicolon, flags.missing_semicolon, "missing semicolon in C-T header.");
        report(cx, Flag::MultipartInvalidQuoting, flags.invalid_quoting, "invalid quoting used.");
        report(cx, Flag::MultipartInvalidPart, flags.invalid_part, "invalid part parsing.");
        report(cx, Flag::MultipartInvalidHeaderFolding, flags.invalid_header_folding, "invalid header folding used.");

        // Known limitation: MULTIPART_FILE_LIMIT_EXCEEDED is never set
        // here; the condition is only reflected in MULTIPART_STRICT_ERROR.
        let strict = flags.error
            || flags.boundary_quoted
            || flags.boundary_whitespace
            || flags.data_before
            || flags.data_after
            || flags.duplicate_part_header
            || flags.header_folding
            || flags.lf_line
            || flags.missing_semicolon
            || flags.invalid_quoting
            || flags.invalid_part
            || flags.invalid_header_folding
            || flags.file_limit_exceeded;
        cx.set(Flag::MultipartStrictError, bit(strict), off);
    }

    /// Sets `MULTIPART_LF_LINE` / `MULTIPART_CRLF_LF_LINES` and logs the
    /// line ending warnings.
    fn set_line_ending_flags(&self, cx: &mut dyn Context) {
        let off = cx.offset();
        cx.set(Flag::MultipartLfLine, bit(self.flags.lf_line), off);
        let mixed = self.flags.crlf_line && self.flags.lf_line;
        cx.set(Flag::MultipartCrlfLfLines, bit(mixed), off);
        if mixed {
            ms_dbg!(cx, 4, "Multipart: Warning: mixed line endings used (CRLF/LF).");
        } else if self.flags.lf_line {
            ms_dbg!(cx, 4, "Multipart: Warning: incorrect line endings used (LF).");
        }
    }

    /// Whether the data left in the buffer is the final boundary, without
    /// a line break after it.
    fn buffer_is_final_boundary(&self) -> bool {
        let end = 2 + self.boundary.len();
        self.buf.len() == end + 2
            && self.buf.starts_with(b"--")
            && self.buf[2..end] == self.boundary[..]
            && self.buf.ends_with(b"--")
    }

    /// The body ends with the final boundary and no line break: the line
    /// was not handled yet. The flags it changes are reported again.
    fn final_boundary_without_line_end(&mut self, cx: &mut dyn Context) {
        let off = cx.offset();
        if self.line_end_at_buffer_end == LineEnd::Lf && !self.flags.lf_line {
            self.flags.lf_line = true;
            self.set_line_ending_flags(cx);
            cx.set(Flag::MultipartStrictError, b"1", off);
        }
        if !self.part_data_read && !self.flags.invalid_part {
            // it looks like the final boundary, but it's where part data
            // should begin
            self.flags.invalid_part = true;
            ms_dbg!(cx, 3, "Multipart: Invalid part (data contains final boundary)");
            cx.set(Flag::MultipartStrictError, b"1", off);
            cx.set(Flag::MultipartInvalidPart, b"1", off);
            ms_dbg!(cx, 4, "Multipart: Warning: invalid part parsing.");
        }

        self.process_boundary(cx, true);
        self.is_complete = true;
    }

    /// Adds the parts to the variables: form fields to `ARGS` and
    /// `ARGS_POST`, files to the `FILES*` ones.
    fn report_parts(&self, cx: &mut dyn Context) {
        let mut file_combined_size: usize = 0;
        for m in &self.parts {
            if m.name.is_empty() {
                continue;
            }

            let Some(file) = m.file() else {
                ms_dbg!(
                    cx,
                    4,
                    "Adding request argument (BODY): name \"{}\", value \"{}\"",
                    String::from_utf8_lossy(&m.name),
                    String::from_utf8_lossy(&m.value)
                );
                let offset = (cx.offset() + 1).wrapping_add(m.value_offset);
                cx.add(Entries::Args, &m.name, &m.value, offset);
                cx.add(Entries::ArgsPost, &m.name, &m.value, offset);
                continue;
            };

            if let Some(f) = &file.tmp_file
                && !f.filename().is_empty()
            {
                let n = f.filename().as_bytes();
                cx.add(Entries::FilesTmpNames, n, n, m.filename_offset);
            }

            // filename* takes precedence over filename, so we set the
            // variable accordingly
            if !m.filename_star.is_empty() {
                cx.add(Entries::Files, &m.name, &m.filename_star, m.filename_star_offset);
            } else if !m.filename.is_empty() {
                cx.add(Entries::Files, &m.name, &m.filename, m.filename_offset);
            }

            cx.add(Entries::FilesNames, &m.name, &m.name, m.name_offset);

            cx.add_with_len(Entries::FilesSizes, &m.name, file.size.to_string().as_bytes(), file.offset, file.size);

            cx.add(Entries::FilesTmpContent, &m.name, &m.value, m.value_offset);

            file_combined_size += file.size;

            cx.set_with_len(Flag::FilesCombinedSize, file_combined_size.to_string().as_bytes(), file.offset, file.size);
        }
    }

    /// Decides what becomes of the temporary files once the transaction is
    /// done with them: the files of the parts are kept with
    /// `SecUploadKeepFiles On`, and deleted otherwise. The file of a part
    /// that was never completed is always deleted. Runs once.
    fn cleanup(&mut self, cx: Option<&dyn Context>) {
        if self.cleaned_up {
            return;
        }
        self.cleaned_up = true;
        ms_dbg_opt!(
            cx,
            4,
            "Multipart: Cleanup started (keep files set to {})",
            match self.upload_keep_files {
                Some(true) => "True",
                Some(false) => "False",
                None => "Not set",
            }
        );

        for m in &self.parts {
            if let Some(f) = m.file().and_then(|file| file.tmp_file.as_ref()) {
                if self.upload_keep_files == Some(true) {
                    f.keep();
                } else {
                    // The file stays on disk until the transaction is
                    // complete.
                    ms_dbg_opt!(cx, 9, "Multipart: Marking temporary file for deletion: {}", f.filename());
                }
            }
        }
    }
}

impl Drop for Multipart {
    /// Runs the cleanup (without its debug messages) if
    /// `multipart_complete` was not called.
    fn drop(&mut self) {
        self.cleanup(None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use modsecurity_types::DebugSink;

    /// A context that keeps the values of `FILES_COMBINED_SIZE`.
    #[derive(Default)]
    struct Sizes(Vec<Vec<u8>>);

    impl DebugSink for Sizes {
        fn debug_enabled(&self, _level: u8) -> bool {
            false
        }
        fn debug(&self, _level: u8, _message: &str) {}
    }

    impl Context for Sizes {
        fn offset(&self) -> usize {
            0
        }
        fn set(&mut self, _flag: Flag, _value: &[u8], _offset: usize) {}
        fn set_with_len(&mut self, flag: Flag, value: &[u8], _offset: usize, _len: usize) {
            if flag == Flag::FilesCombinedSize {
                self.0.push(value.to_vec());
            }
        }
        fn add(&mut self, _entries: Entries, _key: &[u8], _value: &[u8], _offset: usize) {}
        fn add_with_len(&mut self, _entries: Entries, _key: &[u8], _value: &[u8], _offset: usize, _len: usize) {}
        fn uploads(&self) -> Uploads {
            Uploads::default()
        }
        fn upload_file_prefix(&self) -> String {
            String::new()
        }
        fn keep_tmp_file(&mut self, _file: Arc<MultipartPartTmpFile>) {}
    }

    /// `FILES_COMBINED_SIZE` is the sum of the sizes, however large. (It
    /// was kept in a 32 bit integer: two files of 2 GB gave a negative
    /// total, as in C++.)
    #[test]
    fn combined_size_of_large_files() {
        let mut parser = Multipart::new(b"multipart/form-data; boundary=x");
        for name in [&b"a"[..], b"b"] {
            let mut part = MultipartPart::new();
            part.name = name.to_vec();
            part.kind = PartKind::File(part::FilePart { tmp_file: None, size: 2_000_000_000, offset: 1 });
            parser.parts.push(part);
        }
        let mut cx = Sizes::default();
        parser.report_parts(&mut cx);
        assert_eq!(cx.0, [b"2000000000".to_vec(), b"4000000000".to_vec()]);
    }
}
