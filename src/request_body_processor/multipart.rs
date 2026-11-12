//! Port of `src/request_body_processor/multipart.cc`, `src/request_body_processor/multipart.h`.
//!
//! The `multipart/form-data` request body processor. The parser is a line
//! oriented state machine working on an internal buffer of
//! [`MULTIPART_BUF_SIZE`] bytes, exactly as the C++ (and ModSecurity 2)
//! implementation: the data is accumulated until a line feed (or a full
//! buffer) and every buffer is then examined as a possible boundary, part
//! header or part data. Many of the checks treat the buffer as a C string
//! (stopping at the first NUL byte); those semantics are reproduced through
//! the `c_*` helpers below.
//!
//! Form fields end up in `ARGS`/`ARGS_POST`, files in `FILES`,
//! `FILES_NAMES`, `FILES_SIZES`, `FILES_TMP_CONTENT`, `FILES_TMPNAMES`
//! and `FILES_COMBINED_SIZE`, and the anomalies found while parsing in the
//! `MULTIPART_*` flags.

use std::fs::File;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::rules_set_properties::config_boolean_string;
use crate::transaction::Transaction;
use crate::utils::string::{chomp, is_space, lossy};

pub const MULTIPART_BUF_SIZE: usize = 4096;

const MIME_CHARSET_SPECIAL: &[u8] = b"!#$%&+-^_`{}~";
const ATTR_CHAR_SPECIAL: &[u8] = b"!#$&+-.^_`~";

// ---------------------------------------------------------------------------
// C string helpers
// ---------------------------------------------------------------------------

/// The C string starting at `s[0]`: everything up to the first NUL byte.
fn c_str(s: &[u8]) -> &[u8] {
    match s.iter().position(|&c| c == 0) {
        Some(p) => &s[..p],
        None => s,
    }
}

/// `s[i]` of a C string: reading at (or past) the end yields the NUL
/// terminator.
#[inline]
fn c_at(s: &[u8], i: usize) -> u8 {
    s.get(i).copied().unwrap_or(0)
}

/// `strncmp(s + from, needle, strlen(needle)) == 0`, for a `needle` without
/// NUL bytes: the comparison stops at the first difference (a NUL byte in
/// `s` is always a difference).
fn c_starts_with(s: &[u8], from: usize, needle: &[u8]) -> bool {
    needle.iter().enumerate().all(|(k, &n)| c_at(s, from + k) == n)
}

/// `strstr(haystack, needle)` on a NUL free haystack.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

// ---------------------------------------------------------------------------
// MultipartPartTmpFile
// ---------------------------------------------------------------------------

/// A temporary file holding the content of an uploaded file part. It is
/// shared between the part being built and the transaction
/// (`Transaction::multipart_part_tmp_files`), which keeps it (and the file
/// on disk) alive until the transaction is done.
#[derive(Debug)]
pub struct MultipartPartTmpFile {
    tmp_file_name: String,
    /// The open file (`m_tmp_file_fd`); `None` once closed, or when the file
    /// could not be created.
    file: Mutex<Option<File>>,
    /// Whether to delete the file when the transaction is done.
    delete: AtomicBool,
    /// Set once the deletion was handled through
    /// [`MultipartPartTmpFile::release`].
    released: AtomicBool,
}

impl MultipartPartTmpFile {
    /// `MultipartPartTmpFile(transaction)` followed by `Open()`: creates the
    /// file in `SecUploadDir`, named after the current time and the
    /// transaction id.
    fn open(t: &Transaction<'_>) -> Self {
        let tstr = crate::utils::system::strftime_local(crate::utils::system::now(), "/%Y%m%d-%H%M%S");

        let mut path = t.rules.properties.upload_directory.clone().unwrap_or_default();
        path.push_str(&tstr);
        path.push('-');
        path.push_str(&t.id);
        path.push_str("-file-XXXXXX");

        let mut file: Option<File> = None;
        let mut template = path.clone().into_bytes();
        if !template.contains(&0) {
            template.push(0);
            // SAFETY: `template` is a writable, NUL terminated buffer ending
            // in "XXXXXX" as mkstemp requires; mkstemp only rewrites those
            // six characters.
            let fd = unsafe { libc::mkstemp(template.as_mut_ptr() as *mut libc::c_char) };
            template.pop();
            path = String::from_utf8_lossy(&template).into_owned();
            if fd >= 0 {
                use std::os::fd::FromRawFd;
                // SAFETY: mkstemp returned a freshly opened descriptor that
                // nothing else owns.
                file = Some(unsafe { File::from_raw_fd(fd) });
            }
        }
        crate::ms_dbg_a!(t, 4, "MultipartPartTmpFile: Create filename= {}", path);

        let mode = t.rules.properties.upload_file_mode.unwrap_or(0);
        if mode != 0
            && let Some(f) = &file
        {
            use std::os::unix::fs::PermissionsExt;
            if f.set_permissions(std::fs::Permissions::from_mode(mode)).is_err() {
                // The C++ code marked the descriptor as invalid (-1) here,
                // leaking it; it is closed instead.
                file = None;
            }
        }

        MultipartPartTmpFile {
            tmp_file_name: path,
            file: Mutex::new(file),
            delete: AtomicBool::new(false),
            released: AtomicBool::new(false),
        }
    }

    /// `getFilename`
    pub fn get_filename(&self) -> &str {
        &self.tmp_file_name
    }

    /// `setDelete`: delete the file when the transaction is done.
    pub fn set_delete(&self) {
        self.delete.store(true, Ordering::Relaxed);
    }

    /// `isValid`: the file was created (successfully or not: in the latter
    /// case writing reports the failure).
    pub fn is_valid(&self) -> bool {
        !self.tmp_file_name.is_empty()
    }

    fn is_open(&self) -> bool {
        self.file.lock().map(|f| f.is_some()).unwrap_or(false)
    }

    /// `write(fd, data, len) == len`
    fn write(&self, data: &[u8]) -> bool {
        let Ok(guard) = self.file.lock() else {
            return false;
        };
        match guard.as_ref() {
            Some(mut f) => matches!(f.write(data), Ok(n) if n == data.len()),
            None => false,
        }
    }

    /// `Close`
    pub fn close(&self) {
        if let Ok(mut f) = self.file.lock() {
            *f = None;
        }
    }

    /// The C++ destructor: deletes the file if it was marked for deletion,
    /// logging the outcome to the transaction's debug log. The transaction
    /// may call this when it is done with its temporary files; otherwise the
    /// deletion happens (without the debug messages) when the last reference
    /// is dropped.
    pub fn release(&self, t: Option<&Transaction<'_>>) {
        if self.released.swap(true, Ordering::Relaxed) {
            return;
        }
        if self.tmp_file_name.is_empty() || !self.delete.load(Ordering::Relaxed) {
            return;
        }
        // make sure it is closed first
        self.close();

        match std::fs::remove_file(&self.tmp_file_name) {
            Err(e) => {
                let errno = e.raw_os_error().unwrap_or(0);
                crate::ms_dbg_opt!(
                    t,
                    1,
                    "Multipart: Failed to delete file (part) \"{}\" because {}({})",
                    self.tmp_file_name,
                    errno,
                    crate::utils::system::strerror(errno)
                );
            }
            Ok(()) => {
                crate::ms_dbg_opt!(t, 4, "Multipart: file deleted successfully (part) \"{}\"", self.tmp_file_name);
            }
        }
    }
}

impl Drop for MultipartPartTmpFile {
    fn drop(&mut self) {
        self.release(None);
    }
}

// ---------------------------------------------------------------------------
// MultipartPart
// ---------------------------------------------------------------------------

/// `MULTIPART_FORMDATA` / `MULTIPART_FILE`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PartType {
    FormData,
    File,
}

/// Part headers: name -> (offset, value); names compare case insensitively
/// (the C++ `MyHash`/`MyEqual` unordered map).
type PartHeaders = Vec<(Vec<u8>, (usize, Vec<u8>))>;

/// `MultipartPart`
#[derive(Debug)]
struct MultipartPart {
    /// part type, can be `FormData` or `File`
    type_: PartType,

    /// the name
    name: Vec<u8>,
    name_offset: usize,

    /// variables only, variable value
    value: Vec<u8>,
    value_offset: usize,

    value_parts: Vec<(Vec<u8>, u32)>,

    /// files only, the temporary file holding the data
    tmp_file: Option<Arc<MultipartPartTmpFile>>,
    /// (size, offset)
    tmp_file_size: (usize, usize),

    /// files only, filename as supplied by the browser
    filename: Vec<u8>,
    // Note: Every consumer reading the filename must evaluate filename_star
    // first to respect RFC precedence rules before falling back to filename.
    filename_star: Vec<u8>,
    filename_offset: usize,
    filename_star_offset: usize,

    filename_charset: Vec<u8>,
    filename_charset_offset: usize,

    filename_language: Vec<u8>,
    filename_language_offset: usize,

    last_header_name: Vec<u8>,
    headers: PartHeaders,
    last_header_line: Vec<u8>,
    header_lines: Vec<(usize, Vec<u8>)>,

    offset: u32,
    length: u32,
}

impl MultipartPart {
    fn new() -> Self {
        MultipartPart {
            type_: PartType::FormData,
            name: Vec::new(),
            name_offset: 0,
            value: Vec::new(),
            value_offset: 0,
            value_parts: Vec::new(),
            tmp_file: None,
            tmp_file_size: (0, 0),
            filename: Vec::new(),
            filename_star: Vec::new(),
            filename_offset: 0,
            filename_star_offset: 0,
            filename_charset: Vec::new(),
            filename_charset_offset: 0,
            filename_language: Vec::new(),
            filename_language_offset: 0,
            last_header_name: Vec::new(),
            headers: Vec::new(),
            last_header_line: Vec::new(),
            header_lines: Vec::new(),
            offset: 0,
            length: 0,
        }
    }

    fn header(&self, name: &[u8]) -> Option<&(usize, Vec<u8>)> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v)
    }

    fn header_mut(&mut self, name: &[u8]) -> Option<&mut (usize, Vec<u8>)> {
        self.headers.iter_mut().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v)
    }
}

// ---------------------------------------------------------------------------
// Multipart
// ---------------------------------------------------------------------------

/// `Multipart`
#[derive(Debug)]
pub struct Multipart {
    pub reqbody_no_files_length: usize,
    /// The most recent parsing error (`MULTIPART_*` failures and the
    /// upload file limit), reported as `REQBODY_ERROR_MSG`. A later error
    /// replaces an earlier one, as with the C++ `std::string *error`.
    error: Option<String>,
    parts: Vec<MultipartPart>,

    /// Number of parts that are files
    nfiles: i32,

    /// mime boundary used to detect when parts end and begin
    boundary: Vec<u8>,
    boundary_count: i32,

    /// internal buffer and other variables used while parsing
    buf: [u8; MULTIPART_BUF_SIZE + 2],
    buf_contains_line: bool,
    /// Write position in `buf` (`m_bufptr`).
    bufptr: usize,
    bufleft: usize,

    buf_offset: u32,

    /// line ending status seen immediately before current position.
    /// 0 = neither LF nor CR; 1 = prev char CR; 2 = prev char LF alone;
    /// 3 = prev two chars were CRLF
    crlf_state: i32,

    /// crlf_state at end of previous buffer
    crlf_state_buf_end: i32,

    /// the part being built
    mpp: Option<MultipartPart>,

    /// part parsing state; 0 means we are reading headers, 1 means we are
    /// collecting data
    mpp_state: i32,

    /// part parsing substate; if mpp_state is 1 (collecting data), then for
    /// this variable:
    /// 0 means we have not yet read any data between the post-headers blank
    /// line and the next boundary
    /// 1 means we have read at some data after that blank line
    mpp_substate_part_data_read: i32,

    /// because of the way this parsing algorithm works we hold back the last
    /// two bytes of each data chunk so that we can discard it later if the
    /// next data chunk proves to be a boundary; the first byte is an
    /// indicator 0 - no content, 1 - two data bytes available
    reserve: [u8; 4],

    seen_data: bool,
    is_complete: bool,

    flag_error: i32,
    flag_data_before: i32,
    flag_data_after: i32,
    flag_duplicate_part_header: i32,
    flag_header_folding: i32,
    flag_boundary_quoted: i32,
    flag_lf_line: i32,
    flag_crlf_line: i32,
    flag_unmatched_boundary: i32,
    flag_boundary_whitespace: i32,
    flag_missing_semicolon: i32,
    flag_invalid_quoting: i32,
    flag_invalid_part: i32,
    flag_invalid_header_folding: i32,
    flag_file_limit_exceeded: i32,

    header: Vec<u8>,
    /// `SecUploadKeepFiles`, read by the cleanup.
    upload_keep_files: Option<bool>,
    /// Whether the cleanup of the C++ destructor already ran.
    cleaned_up: bool,
}

impl Multipart {
    /// `Multipart(header, transaction)`: `header` is the Content-Type.
    pub fn new(header: &[u8]) -> Self {
        Multipart {
            reqbody_no_files_length: 0,
            parts: Vec::new(),
            nfiles: 0,
            boundary: Vec::new(),
            boundary_count: 0,
            buf: [0; MULTIPART_BUF_SIZE + 2],
            buf_contains_line: false,
            bufptr: 0,
            bufleft: 0,
            buf_offset: 0,
            crlf_state: 0,
            crlf_state_buf_end: 0,
            mpp: None,
            mpp_state: 0,
            mpp_substate_part_data_read: 0,
            reserve: [0; 4],
            seen_data: false,
            is_complete: false,
            flag_error: 0,
            error: None,
            flag_data_before: 0,
            flag_data_after: 0,
            flag_duplicate_part_header: 0,
            flag_header_folding: 0,
            flag_boundary_quoted: 0,
            flag_lf_line: 0,
            flag_crlf_line: 0,
            flag_unmatched_boundary: 0,
            flag_boundary_whitespace: 0,
            flag_missing_semicolon: 0,
            flag_invalid_quoting: 0,
            flag_invalid_part: 0,
            flag_invalid_header_folding: 0,
            flag_file_limit_exceeded: 0,
            header: header.to_vec(),
            upload_keep_files: None,
            cleaned_up: false,
        }
    }

    /// `is_token_char`
    pub fn is_token_char(c: u8) -> bool {
        // CTLs not allowed
        if c <= 32 || c >= 127 {
            return false;
        }
        !matches!(
            c,
            b'(' | b')' | b'<' | b'>' | b'@' | b',' | b';' | b':' | b'\\' | b'"' | b'/' | b'[' | b']' | b'?' | b'='
        )
    }

    /// `boundary_characters_valid`
    pub fn boundary_characters_valid(boundary: &[u8]) -> bool {
        let boundary = c_str(boundary);
        boundary.iter().enumerate().all(|(i, &c)| {
            // Check against allowed list defined in RFC2046 page 22
            c.is_ascii_alphanumeric()
                // space allowed, but not as last character
                || (c == b' ' && i + 1 < boundary.len())
                || matches!(c, b'\'' | b'(' | b')' | b'+' | b'_' | b',' | b'-' | b'.' | b'/' | b':' | b'=' | b'?')
        })
    }

    /// `count_boundary_params`: how many times the word "boundary" followed
    /// (anywhere later) by `=` appears, case insensitively.
    pub fn count_boundary_params(str_header_value: &[u8]) -> i32 {
        let lower = str_header_value.to_ascii_lowercase();
        let mut s = c_str(&lower);
        let mut count = 0;
        while let Some(p) = find(s, b"boundary") {
            s = &s[p + 8..];
            if s.contains(&b'=') {
                count += 1;
            }
        }
        count
    }

    /// `validate_quotes`
    fn validate_quotes(&mut self, t: &Transaction<'_>, data: &[u8], quote: u8) {
        // if the value was enclosed in double quotes, then we don't care
        // about a single quote character within the name.
        if quote == b'"' {
            return;
        }
        for &c in data {
            if c == b'\'' {
                crate::ms_dbg_a!(
                    t,
                    9,
                    "Multipart: Invalid quoting detected: {} length {} bytes",
                    lossy(data),
                    data.len()
                );
                self.flag_invalid_quoting = 1;
            }
        }
    }

    /// `parse_content_disposition`: `c_d_value` is the header value (a C
    /// string), `offset` where it starts.
    fn parse_content_disposition(&mut self, t: &mut Transaction<'_>, c_d_value: &[u8], offset: usize) -> i32 {
        let cd = c_str(c_d_value);
        let at = |i: usize| c_at(cd, i);

        // accept only what we understand
        if !cd.starts_with(b"form-data") {
            return -1;
        }

        // see if there are any other parts to parse
        let mut p = 9;
        while at(p) == b'\t' || at(p) == b' ' {
            p += 1;
        }
        if at(p) == 0 {
            return 1; // this is OK
        }

        if at(p) != b';' {
            return -2;
        }
        p += 1;

        // parse the appended parts
        while at(p) != 0 {
            let mut value: Vec<u8> = Vec::new();

            // go over the whitespace
            while at(p) == b'\t' || at(p) == b' ' {
                p += 1;
            }

            if at(p) == 0 {
                return -3;
            }

            let start = p;
            while at(p) != 0 && at(p) != b'=' && at(p) != b'\t' && at(p) != b' ' {
                p += 1;
            }

            if at(p) == 0 {
                return -4;
            }

            let name = &cd[start..p];

            while at(p) == b'\t' || at(p) == b' ' {
                p += 1;
            }

            if at(p) == 0 {
                return -5;
            }

            if at(p) != b'=' {
                return -13;
            }

            p += 1;

            while at(p) == b'\t' || at(p) == b' ' {
                p += 1;
            }

            if at(p) == 0 {
                return -6;
            }

            let mpp = self.mpp.as_mut().expect("part being built");
            let mut quote = 0u8;
            if name == b"filename*" {
                // filename*=charset'[optional-language]'filename
                // Read beyond the charset and the optional language
                let start_of_charset = p;
                while at(p) != 0 && (at(p).is_ascii_alphanumeric() || MIME_CHARSET_SPECIAL.contains(&at(p))) {
                    p += 1;
                }
                if at(p) != b'\'' || p == start_of_charset {
                    // Must be at least one legit char before ' for start of
                    // language
                    return -16;
                }
                mpp.filename_charset = cd[start_of_charset..p].to_vec();
                mpp.filename_charset_offset = offset.wrapping_add(p - mpp.filename_charset.len());
                crate::ms_dbg_a!(
                    t,
                    4,
                    "Multipart: Content-Disposition filename* charset: {}.",
                    lossy(&mpp.filename_charset)
                );
                p += 1;
                // Read beyond the charset and the optional language
                let start_of_language = p;
                while at(p) != 0 && at(p) != b'\'' {
                    p += 1;
                }
                if at(p) != b'\'' {
                    self.flag_invalid_quoting = 1;
                    return -17; // Single quote for end-of-language not found
                }
                mpp.filename_language = cd[start_of_language..p].to_vec();
                mpp.filename_language_offset = offset.wrapping_add(p - mpp.filename_language.len());
                crate::ms_dbg_a!(
                    t,
                    4,
                    "Multipart: Content-Disposition filename* language: {}.",
                    lossy(&mpp.filename_language)
                );
                p += 1;

                // Now read what should be the actual filename
                let start_of_filename = p;
                while at(p) != 0 && at(p) != b';' {
                    if at(p) == b'%' {
                        if at(p + 1) == 0
                            || at(p + 2) == 0
                            || !at(p + 1).is_ascii_hexdigit()
                            || !at(p + 2).is_ascii_hexdigit()
                        {
                            return -18;
                        }
                        p += 3;
                    } else if at(p).is_ascii_alphanumeric() || ATTR_CHAR_SPECIAL.contains(&at(p)) {
                        p += 1;
                    } else {
                        return -19;
                    }
                }
                value = cd[start_of_filename..p].to_vec();
            } else if at(p) == b'"' || at(p) == b'\'' {
                // Accept both quotes as some backends will accept them, but
                // technically "'" is invalid and so flag_invalid_quoting is
                // set so the user can deal with it in the rules if they so
                // wish.
                quote = at(p); // remember which quote character was used for the value

                if quote == b'\'' {
                    self.flag_invalid_quoting = 1;
                }

                p += 1;
                if at(p) == 0 {
                    return -7;
                }

                while at(p) != 0 {
                    if at(p) == b'\\' {
                        if at(p + 1) == 0 {
                            // improper escaping
                            return -8;
                        }
                        // only quote and \ can be escaped
                        if at(p + 1) == quote || at(p + 1) == b'\\' {
                            p += 1;
                        } else {
                            // improper escaping

                            // We allow for now because IE sends
                            // improperly escaped content and there's
                            // nothing we can do about it.
                            //
                            // return -9;
                        }
                    } else if at(p) == quote {
                        break;
                    }

                    value.push(at(p));
                    p += 1;
                }

                if at(p) == quote {
                    p += 1; // go over the quote at the end
                } else {
                    self.flag_invalid_quoting = 1;
                    return -15; // closing quote not found
                }
            } else {
                // not quoted
                let start = p;
                while at(p) != 0 && Self::is_token_char(at(p)) {
                    p += 1;
                }
                value = cd[start..p].to_vec();
            }

            // evaluate part
            let value_offset = offset.wrapping_add(p - value.len());
            if name == b"name" {
                self.validate_quotes(t, &value, quote);

                t.vars.multipart_name.set(&value, &value, value_offset);

                let mpp = self.mpp.as_mut().expect("part being built");
                if !mpp.name.is_empty() {
                    self.flag_duplicate_part_header = 1;
                    crate::ms_dbg_a!(
                        t,
                        4,
                        "Multipart: Warning: Duplicate Content-Disposition name: {}. Previously: {}",
                        lossy(&value),
                        lossy(&mpp.name)
                    );
                    return -14;
                }
                mpp.name = value.clone();
                mpp.name_offset = value_offset;
                crate::ms_dbg_a!(t, 9, "Multipart: Content-Disposition name: {}.", lossy(&value));
            } else if name == b"filename" {
                // here we set up the 'filename' only if it's not set up
                // already (and not the filename_star)
                if !self.mpp.as_ref().expect("part being built").filename.is_empty() {
                    self.flag_duplicate_part_header = 1;
                    crate::ms_dbg_a!(
                        t,
                        4,
                        "Multipart: Warning: Duplicate Content-Disposition filename: {}.",
                        lossy(&value)
                    );
                    return -15;
                } else {
                    self.validate_quotes(t, &value, quote);
                    let mpp = self.mpp.as_mut().expect("part being built");
                    mpp.filename = value.clone();
                    mpp.filename_offset = value_offset;

                    crate::ms_dbg_a!(t, 9, "Multipart: Content-Disposition filename: {}.", lossy(&value));
                }
            } else if name == b"filename*" {
                // here we set up the 'filename_star' only if it's not set up
                // already (and not the filename)
                if !self.mpp.as_ref().expect("part being built").filename_star.is_empty() {
                    self.flag_duplicate_part_header = 1;
                    crate::ms_dbg_a!(
                        t,
                        4,
                        "Multipart: Warning: Duplicate Content-Disposition filename*: {}.",
                        lossy(&value)
                    );
                    return -15;
                }

                let mut invalid_count = 0;
                let mut decoded_value = value.clone();
                crate::utils::decode::urldecode_nonstrict_inplace_ext(&mut decoded_value, false, &mut invalid_count);
                if invalid_count > 0 {
                    self.flag_invalid_part = 1;
                }
                let mpp = self.mpp.as_mut().expect("part being built");
                mpp.filename_star = decoded_value;
                mpp.filename_star_offset = value_offset;
                crate::ms_dbg_a!(t, 9, "Multipart: Content-Disposition filename*: {}.", lossy(&mpp.filename_star));
            } else {
                return -11;
            }

            if at(p) != 0 {
                while at(p) == b'\t' || at(p) == b' ' {
                    p += 1;
                }

                // the next character must be a zero or a semi-colon
                if at(p) == 0 {
                    // Just let the 'while' condition end the loop
                } else {
                    if at(p) != b';' {
                        p -= 1;
                        if at(p) == b'\'' || at(p) == b'"' {
                            crate::ms_dbg_a!(
                                t,
                                9,
                                "Multipart: Invalid quoting detected: {} length {} bytes",
                                lossy(&cd[p..]),
                                cd.len() - p
                            );
                            self.flag_invalid_quoting = 1;
                        }
                        // p++;
                        return -12;
                    }
                    p += 1; // move over the semi-colon
                }
            }

            // loop will stop when at(p) == 0
        }

        // filename* takes precedence over filename, so we set the variable
        // accordingly
        let mpp = self.mpp.as_ref().expect("part being built");
        if !mpp.filename_star.is_empty() {
            t.vars.multipart_file_name.set(&mpp.name, &mpp.filename_star, mpp.filename_star_offset);

            if !mpp.filename_charset.is_empty() {
                t.vars.multipart_file_name_charset.set(&mpp.name, &mpp.filename_charset, mpp.filename_charset_offset);
            }
            if !mpp.filename_language.is_empty() {
                t.vars.multipart_file_name_language.set(
                    &mpp.name,
                    &mpp.filename_language,
                    mpp.filename_language_offset,
                );
            }
        } else if !mpp.filename.is_empty() {
            t.vars.multipart_file_name.set(&mpp.name, &mpp.filename, mpp.filename_offset);
        }

        1
    }

    /// `process_part_data`
    fn process_part_data(&mut self, t: &mut Transaction<'_>, offset: usize) -> bool {
        let p = MULTIPART_BUF_SIZE - self.bufleft;
        let mut localreserve = [0u8; 2];
        let mut bytes_reserved: u8 = 0;

        self.mpp_substate_part_data_read = 1;

        // Preserve some bytes for later.
        if p >= 1 && self.buf[p - 1] == b'\n' {
            if p >= 2 && self.buf[p - 2] == b'\r' {
                // Two bytes.
                bytes_reserved = 2;
                localreserve[0] = self.buf[p - 2];
                localreserve[1] = self.buf[p - 1];
                self.bufleft += 2;
                self.buf[p - 2] = 0;
            } else {
                // Only one byte.
                bytes_reserved = 1;
                localreserve[0] = self.buf[p - 1];
                localreserve[1] = 0;
                self.bufleft += 1;
                self.buf[p - 1] = 0;
            }
        }

        let len = MULTIPART_BUF_SIZE - self.bufleft;
        let reserved = self.reserve[0] as usize;
        let props = &t.rules.properties;
        let mpp = self.mpp.as_mut().expect("part being built");

        // add data to the part we are building
        match mpp.type_ {
            PartType::File => {
                let mut extract = props.upload_keep_files == Some(true) || props.tmp_save_uploaded_files == Some(true);

                // remember where we started
                if mpp.length == 0 {
                    mpp.offset = self.buf_offset;
                }

                // check if the file limit has been reached
                let limit = props.upload_file_limit.unwrap_or(0);
                if extract && limit != 0 && self.nfiles as u32 >= limit {
                    if self.flag_file_limit_exceeded == 0 {
                        crate::ms_dbg_a!(
                            t,
                            1,
                            "Multipart: Upload file limit exceeded {}. Use SecUploadFileLimit to change the limit.",
                            limit
                        );
                        self.error = Some(format!(
                            "Multipart: Upload file limit exceeded {}. Use SecUploadFileLimit to change the limit.",
                            limit
                        ));
                        self.flag_file_limit_exceeded = 1;
                    }
                    extract = false;
                }

                // only store individual files on disk if we are going to
                // keep them or if we need to have them approved later
                if extract {
                    // first create a temporary file if we don't have it
                    // already
                    if !mpp.tmp_file.as_ref().is_some_and(|f| f.is_valid()) {
                        let tmp = Arc::new(MultipartPartTmpFile::open(t));
                        t.multipart_part_tmp_files.push(Arc::clone(&tmp));
                        mpp.tmp_file = Some(Arc::clone(&tmp));

                        // do we have an opened file?
                        if !tmp.is_open() {
                            crate::ms_dbg_a!(t, 1, "Multipart: Failed to create file: {}", tmp.get_filename());
                            self.error = Some(format!("Multipart: Failed to create file: {}", tmp.get_filename()));
                            return false;
                        }
                        // keep track of the files count
                        self.nfiles += 1;

                        crate::ms_dbg_a!(
                            t,
                            4,
                            "Multipart: Created temporary file {} (mode 0{:o}): {}",
                            self.nfiles,
                            t.rules.properties.upload_file_mode.unwrap_or(0),
                            tmp.get_filename()
                        );
                    }
                    let tmp = mpp.tmp_file.as_ref().expect("temporary file");

                    // write the reserve first
                    if reserved != 0 {
                        if !tmp.write(&self.reserve[1..1 + reserved]) {
                            crate::ms_dbg_a!(t, 1, "Multipart: writing to \"{}\" failed", tmp.get_filename());
                            self.error = Some(format!("Multipart: writing to \"{}\" failed", tmp.get_filename()));
                            return false;
                        }

                        mpp.tmp_file_size.0 += reserved;
                        if mpp.tmp_file_size.1 == 0 {
                            mpp.tmp_file_size.1 = offset.wrapping_sub(mpp.tmp_file_size.0);
                        }
                        mpp.length = mpp.length.wrapping_add(reserved as u32);
                    }

                    // write data to the file
                    if !tmp.write(&self.buf[..len]) {
                        crate::ms_dbg_a!(t, 1, "Multipart: writing to \"{}\" failed", tmp.get_filename());
                        self.error = Some(format!("Multipart: writing to \"{}\" failed", tmp.get_filename()));
                        return false;
                    }

                    mpp.value.extend_from_slice(&self.buf[..len]);
                    mpp.value_offset = offset.wrapping_sub(len);

                    mpp.tmp_file_size.0 += len;
                    if mpp.tmp_file_size.1 == 0 {
                        mpp.tmp_file_size.1 = offset.wrapping_sub(mpp.tmp_file_size.0);
                    }

                    mpp.length = mpp.length.wrapping_add(len as u32);
                } else {
                    // just keep track of the file size
                    mpp.tmp_file_size.0 += len + reserved;
                    if mpp.tmp_file_size.1 == 0 {
                        mpp.tmp_file_size.1 = offset.wrapping_sub(mpp.tmp_file_size.0);
                    }

                    mpp.length = mpp.length.wrapping_add((len + reserved) as u32);
                }
            }
            PartType::FormData => {
                // The buffer contains data so increase the data length
                // counter.
                self.reqbody_no_files_length += len + reserved;

                // add this part to the list of parts

                // remember where we started
                if mpp.length == 0 {
                    mpp.offset = self.buf_offset;
                }

                let mut d: Vec<u8> = Vec::with_capacity(reserved + len);
                d.extend_from_slice(&self.reserve[1..1 + reserved]);
                d.extend_from_slice(&self.buf[..len]);
                mpp.length = mpp.length.wrapping_add(d.len() as u32);

                crate::ms_dbg_a!(t, 9, "Multipart: Added data to variable: {}", lossy(&d));
                mpp.value_parts.push((d, self.buf_offset));
            }
        }

        // store the reserved bytes to the multipart context so that they
        // don't get lost
        if bytes_reserved != 0 {
            self.reserve[0] = bytes_reserved;
            self.reserve[1] = localreserve[0];
            self.reserve[2] = localreserve[1];
            self.buf_offset = self.buf_offset.wrapping_add(u32::from(bytes_reserved));
        } else {
            self.buf_offset = self.buf_offset.wrapping_sub(u32::from(self.reserve[0]));
            self.reserve[0] = 0;
        }

        true
    }

    /// `process_part_header`. Like the C++ code (whose failures return 0,
    /// which its caller does not treat as fatal), a failure only records
    /// the error.
    fn process_part_header(&mut self, t: &mut Transaction<'_>, offset: usize) {
        // Check for nul bytes.
        let len = MULTIPART_BUF_SIZE - self.bufleft;
        let mut len_without_termination = len as isize - 1;
        if self.buf[..len].contains(&0) {
            crate::ms_dbg_a!(t, 1, "Multipart: Nul byte in part headers.");
            self.error = Some("Multipart: Nul byte in part headers.".to_string());
            return;
        }

        let mut i: usize = 0;
        // The buffer is data so increase the data length counter.
        self.reqbody_no_files_length += len;

        if len > 1 {
            if self.buf[len - 2] == b'\r' {
                self.flag_crlf_line = 1;
                len_without_termination -= 1;
            } else {
                self.flag_lf_line = 1;
            }
        } else {
            self.flag_lf_line = 1;
        }

        let buf = &self.buf;
        let line = c_str(&buf[..]);

        // Is this an empty line?
        if (buf[0] == b'\r' && buf[1] == b'\n' && buf[2] == 0) || (buf[0] == b'\n' && buf[1] == 0) {
            // Empty line.
            let mpp = self.mpp.as_mut().expect("part being built");

            // record the previous completed header
            if !mpp.last_header_line.is_empty() {
                let l = std::mem::take(&mut mpp.last_header_line);
                mpp.header_lines.push((offset.wrapping_sub(l.len()), l));
            }

            let Some((cd_offset, header_value)) = mpp.header(b"Content-Disposition").cloned() else {
                crate::ms_dbg_a!(t, 1, "Multipart: Part missing Content-Disposition header.");
                self.error = Some("Multipart: Part missing Content-Disposition header.".to_string());
                return;
            };

            let rc = self.parse_content_disposition(t, &header_value, cd_offset);
            if rc < 0 {
                crate::ms_dbg_a!(
                    t,
                    1,
                    "Multipart: Invalid Content-Disposition header ({}): {}",
                    rc,
                    lossy(&header_value)
                );
                self.error =
                    Some(format!("Multipart: Invalid Content-Disposition header ({}): {}", rc, lossy(&header_value)));
                return;
            }

            let mpp = self.mpp.as_mut().expect("part being built");
            if mpp.name.is_empty() {
                crate::ms_dbg_a!(t, 1, "Multipart: Content-Disposition header missing name field.");
                self.error = Some("Multipart: Content-Disposition header missing name field.".to_string());
                return;
            }

            if !mpp.filename.is_empty() || !mpp.filename_star.is_empty() {
                // Some parsers use crude methods to extract the name and
                // filename values from the C-D header. We need to check for
                // the case where they didn't understand C-D but we did.
                //
                // also we need to check if any of the filename or filename*
                // is present
                let hv = c_str(&header_value);
                if find(hv, b"filename=").is_none() && find(hv, b"filename*=").is_none() {
                    crate::ms_dbg_a!(t, 1, "Multipart: Invalid Content-Disposition header (filename).");
                    self.error = Some("Multipart: Invalid Content-Disposition header (filename).".to_string());
                    return;
                }

                mpp.type_ = PartType::File;
            } else {
                mpp.type_ = PartType::FormData;
            }

            self.mpp_state = 1;
            self.mpp_substate_part_data_read = 0;
            mpp.last_header_name.clear();
        } else if is_space(buf[0]) {
            // Header line.

            // header folding, add data to the header we are building
            self.flag_header_folding = 1;

            // RFC-2557 states header folding is SP / HTAB, but PHP and
            // perhaps others will take any whitespace.  So, we accept, but
            // with a flag set.
            if buf[0] != b'\t' && buf[0] != b' ' {
                self.flag_invalid_header_folding = 1;
            }

            let mpp = self.mpp.as_mut().expect("part being built");
            if mpp.last_header_name.is_empty() {
                // we are not building a header at this moment
                crate::ms_dbg_a!(t, 1, "Multipart: Invalid part header (folding error).");
                self.error = Some("Multipart: Invalid part header (folding error).".to_string());
                return;
            }

            // locate the beginning of data
            let mut data = 0;
            while is_space(c_at(line, data)) {
                // Flag invalid header folding if an invalid RFC-2557
                // character is used anywhere in the folding prefix.
                if line[data] != b'\t' && line[data] != b' ' {
                    self.flag_invalid_header_folding = 1;
                }
                data += 1;
            }

            let mut new_value = line[data..].to_vec();
            chomp(&mut new_value);

            // update the header value in the table
            let last_header_name = mpp.last_header_name.clone();
            let entry = mpp.header_mut(&last_header_name).expect("header being built");
            let mut v = entry.1.clone();
            v.push(b' ');
            v.extend_from_slice(&new_value);
            let new_value = v;
            entry.1 = new_value.clone();

            crate::ms_dbg_a!(
                t,
                9,
                "Multipart: Continued folder header \"{}\" with \"{}\"",
                lossy(&last_header_name),
                lossy(&line[data..])
            );

            if new_value.len() > MULTIPART_BUF_SIZE {
                crate::ms_dbg_a!(t, 1, "Multipart: Part header too long.");
                self.error = Some("Multipart: Part header too long.".to_string());
                return;
            }

            let mut l = last_header_name;
            l.extend_from_slice(b": ");
            l.extend_from_slice(&new_value);
            mpp.last_header_line = l;
        } else {
            // new header
            let mpp = self.mpp.as_mut().expect("part being built");

            // record the previous completed header
            if !mpp.last_header_line.is_empty() {
                let l = std::mem::take(&mut mpp.last_header_line);
                mpp.header_lines.push((offset.wrapping_sub(l.len()), l));
            }

            let mut data = 0;
            while c_at(line, data) != b':' && c_at(line, data) != 0 {
                data += 1;
                i += 1;
            }
            if c_at(line, data) == 0 {
                crate::ms_dbg_a!(t, 1, "Multipart: Invalid part header (colon missing): {}", lossy(line));
                self.error = Some(format!("Multipart: Invalid part header (colon missing): {}", lossy(line)));
                return;
            }

            // extract header name
            let header_name = line[..data].to_vec();
            if data == 0 {
                crate::ms_dbg_a!(t, 1, "Multipart: Invalid part header (header name missing).");
                self.error = Some("Multipart: Invalid part header (header name missing).".to_string());
                return;
            }

            // check if multipart header contains any invalid characters
            if header_name.iter().any(|&ch| !(33..=126).contains(&ch)) {
                crate::ms_dbg_a!(t, 1, "Multipart: Invalid part header (contains invalid character).");
                self.error = Some("Multipart: Invalid part header (contains invalid character).".to_string());
                return;
            }

            // extract the value value
            data += 1;
            i += 1;
            while c_at(line, data) == b'\t' || c_at(line, data) == b' ' {
                data += 1;
                i += 1;
            }
            let mut header_value = line[data..].to_vec();
            chomp(&mut header_value);

            // error if the name already exists
            if mpp.header(&header_name).is_some() {
                self.flag_duplicate_part_header = 1;
                crate::ms_dbg_a!(t, 1, "Multipart: Duplicate part header: {}.", lossy(&header_name));
                return;
            }

            mpp.last_header_name = header_name.clone();

            crate::ms_dbg_a!(
                t,
                9,
                "Multipart: Added part header \"{}\" \"{}\".",
                lossy(&header_name),
                lossy(&header_value)
            );
            mpp.headers.push((header_name, (offset.wrapping_sub(len).wrapping_add(i), header_value)));
            if len_without_termination > 0 {
                mpp.last_header_line = buf[..len_without_termination as usize].to_vec();
            } else {
                mpp.last_header_line.clear();
            }
        }
    }

    /// `process_boundary`
    fn process_boundary(&mut self, t: &mut Transaction<'_>, last_part: bool) -> i32 {
        // if there was a part being built finish it
        if let Some(mut mpp) = self.mpp.take() {
            // record all the part header lines from the part into the
            // transaction collection
            for (off, line) in &mpp.header_lines {
                t.vars.multipart_part_headers.set(&mpp.name, line, *off);
                crate::ms_dbg_a!(t, 9, "Multipart: Added part header line:{}", lossy(line));
            }

            // close the temp file
            if mpp.type_ == PartType::File
                && let Some(f) = &mpp.tmp_file
                && f.is_valid()
            {
                f.close();
            }

            if mpp.type_ != PartType::File {
                // now construct a single string out of the parts
                for (d, off) in &mpp.value_parts {
                    if mpp.value_offset == 0 {
                        mpp.value_offset = *off as usize;
                    }
                    mpp.value.extend_from_slice(d);
                }
            }

            if !mpp.name.is_empty() {
                // add the part to the list of parts

                // see the inline condition
                // filename* takes precedence over filename, so we set the
                // variable accordingly
                if mpp.type_ == PartType::File {
                    let fname = if !mpp.filename_star.is_empty() { &mpp.filename_star } else { &mpp.filename };
                    crate::ms_dbg_a!(
                        t,
                        9,
                        "Multipart: Added file part to the list: name \"{}\" file name \"{}\" (offset {}, length {})",
                        lossy(&mpp.name),
                        lossy(fname),
                        mpp.offset,
                        mpp.length
                    );
                } else {
                    crate::ms_dbg_a!(
                        t,
                        9,
                        "Multipart: Added part to the list: name \"{}\" (offset {}, length {})",
                        lossy(&mpp.name),
                        mpp.offset,
                        mpp.length
                    );
                }
                self.parts.push(mpp);
            } else {
                self.flag_invalid_part = 1;
                crate::ms_dbg_a!(
                    t,
                    3,
                    "Multipart: Skipping invalid part (part name missing): (offset {}, length {})",
                    mpp.offset,
                    mpp.length
                );
            }
        }

        if !last_part {
            // start building a new part
            self.mpp = Some(MultipartPart::new());

            self.mpp_state = 0;
            self.mpp_substate_part_data_read = 0;

            self.reserve = [0; 4];
        }

        1
    }

    /// Sets `MULTIPART_LF_LINE` / `MULTIPART_CRLF_LF_LINES` and logs the
    /// line ending warnings.
    fn set_line_ending_flags(&self, t: &mut Transaction<'_>) {
        let off = t.vars.offset;
        t.vars.multipart_lf_line.set(self.flag_lf_line.to_string().as_bytes(), off);
        let mixed = self.flag_crlf_line != 0 && self.flag_lf_line != 0;
        t.vars.multipart_crlf_lf_lines.set(if mixed { b"1" } else { b"0" }, off);
        if mixed {
            crate::ms_dbg_a!(t, 4, "Multipart: Warning: mixed line endings used (CRLF/LF).");
        } else if self.flag_lf_line != 0 {
            crate::ms_dbg_a!(t, 4, "Multipart: Warning: incorrect line endings used (LF).");
        }
    }

    /// `multipart_complete`: finalizes multipart processing. This method is
    /// invoked at the end, when it is clear that there is no more data to be
    /// processed.
    ///
    /// The cleanup the C++ destructor did (marking the temporary files for
    /// deletion, with its debug messages) needs the transaction, so it runs
    /// at the end of this method: `Transaction::processRequestBody` always
    /// destroyed the processor right after calling `multipart_complete`.
    /// The error to report, if processing failed.
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    pub fn multipart_complete(&mut self, t: &mut Transaction<'_>) -> bool {
        let ret = self.complete(t);
        self.cleanup(Some(t));
        ret
    }

    fn complete(&mut self, t: &mut Transaction<'_>) -> bool {
        fn flag(t: &mut Transaction<'_>, f: i32) -> (Vec<u8>, usize) {
            (f.to_string().into_bytes(), t.vars.offset)
        }

        let (v, off) = flag(t, self.flag_unmatched_boundary);
        t.vars.multipart_unmatched_boundary.set(&v, off);

        let (v, off) = flag(t, self.flag_data_before);
        t.vars.multipart_data_before.set(&v, off);
        if self.flag_data_before != 0 {
            crate::ms_dbg_a!(t, 4, "Multipart: Warning: seen data before first boundary.");
        }

        let (v, off) = flag(t, self.flag_data_after);
        t.vars.multipart_data_after.set(&v, off);
        if self.flag_data_after != 0 {
            crate::ms_dbg_a!(t, 4, "Multipart: Warning: seen data after last boundary.");
        }

        let (v, off) = flag(t, self.flag_duplicate_part_header);
        t.vars.multipart_duplicate_part_header.set(&v, off);
        if self.flag_duplicate_part_header != 0 {
            crate::ms_dbg_a!(t, 4, "Multipart: Warning: seen duplicate part header.");
        }

        let (v, off) = flag(t, self.flag_boundary_quoted);
        t.vars.multipart_boundary_quoted.set(&v, off);
        if self.flag_boundary_quoted != 0 {
            crate::ms_dbg_a!(t, 4, "Multipart: Warning: boundary was quoted.");
        }

        let (v, off) = flag(t, self.flag_boundary_whitespace);
        t.vars.multipart_boundary_white_space.set(&v, off);
        if self.flag_boundary_whitespace != 0 {
            crate::ms_dbg_a!(t, 4, "Multipart: Warning: boundary whitespace in C-T header.");
        }

        let (v, off) = flag(t, self.flag_header_folding);
        t.vars.multipart_header_folding.set(&v, off);
        if self.flag_header_folding != 0 {
            crate::ms_dbg_a!(t, 4, "Multipart: Warning: header folding used.");
        }
        self.set_line_ending_flags(t);

        let (v, off) = flag(t, self.flag_missing_semicolon);
        t.vars.multipart_missing_semicolon.set(&v, off);
        if self.flag_missing_semicolon != 0 {
            crate::ms_dbg_a!(t, 4, "Multipart: Warning: missing semicolon in C-T header.");
        }

        let (v, off) = flag(t, self.flag_invalid_quoting);
        t.vars.multipart_invalid_quoting.set(&v, off);
        if self.flag_invalid_quoting != 0 {
            crate::ms_dbg_a!(t, 4, "Multipart: Warning: invalid quoting used.");
        }

        let (v, off) = flag(t, self.flag_invalid_part);
        t.vars.multipart_invalid_part.set(&v, off);
        if self.flag_invalid_part != 0 {
            crate::ms_dbg_a!(t, 4, "Multipart: Warning: invalid part parsing.");
        }

        let (v, off) = flag(t, self.flag_invalid_header_folding);
        t.vars.multipart_invalid_header_folding.set(&v, off);
        if self.flag_invalid_header_folding != 0 {
            crate::ms_dbg_a!(t, 4, "Multipart: Warning: invalid header folding used.");
        }

        // Note: like the C++ code, MULTIPART_FILE_LIMIT_EXCEEDED is never
        // set; the condition is only reflected in MULTIPART_STRICT_ERROR.
        let strict = self.flag_error != 0
            || self.flag_boundary_quoted != 0
            || self.flag_boundary_whitespace != 0
            || self.flag_data_before != 0
            || self.flag_data_after != 0
            || self.flag_duplicate_part_header != 0
            || self.flag_header_folding != 0
            || self.flag_lf_line != 0
            || self.flag_missing_semicolon != 0
            || self.flag_invalid_quoting != 0
            || self.flag_invalid_part != 0
            || self.flag_invalid_header_folding != 0
            || self.flag_file_limit_exceeded != 0;
        let off = t.vars.offset;
        t.vars.multipart_strict_error.set(if strict { b"1" } else { b"0" }, off);

        if self.seen_data && !self.is_complete {
            if self.boundary_count > 0 {
                // Check if we have the final boundary (that we haven't
                // processed yet) in the buffer.
                if self.buf_contains_line {
                    let blen = self.boundary.len();
                    let buf = &self.buf;
                    if MULTIPART_BUF_SIZE - self.bufleft == 4 + blen
                        && buf[0] == b'-'
                        && buf[1] == b'-'
                        && c_starts_with(buf, 2, &self.boundary)
                        && buf[2 + blen] == b'-'
                        && buf[2 + blen + 1] == b'-'
                    {
                        // these next two checks may result in repeating work
                        // from earlier in this fn; ignore the duplication for
                        // now to minimize refactoring
                        if self.crlf_state_buf_end == 2 && self.flag_lf_line != 1 {
                            self.flag_lf_line = 1;
                            self.set_line_ending_flags(t);
                            let (v, off) = flag(t, self.flag_lf_line);
                            t.vars.multipart_strict_error.set(&v, off);
                        }
                        if self.mpp_substate_part_data_read == 0 && self.flag_invalid_part != 1 {
                            // it looks like the final boundary, but it's
                            // where part data should begin
                            self.flag_invalid_part = 1;
                            crate::ms_dbg_a!(t, 3, "Multipart: Invalid part (data contains final boundary)");
                            let (v, off) = flag(t, self.flag_invalid_part);
                            t.vars.multipart_strict_error.set(&v, off);
                            t.vars.multipart_invalid_part.set(&v, off);
                            crate::ms_dbg_a!(t, 4, "Multipart: Warning: invalid part parsing.");
                        }

                        // Looks like the final boundary - process it.
                        if self.process_boundary(t, true) < 0 {
                            self.flag_error = 1;
                            return false;
                        }

                        // The payload is complete after all.
                        self.is_complete = true;
                    }
                }

                if !self.is_complete {
                    crate::ms_dbg_a!(t, 1, "Multipart: Final boundary missing.");
                    self.error = Some("Multipart: Final boundary missing.".to_string());
                    return false;
                }
            } else {
                crate::ms_dbg_a!(t, 1, "Multipart: No boundaries found in payload.");
                self.error = Some("Multipart: No boundaries found in payload.".to_string());
                return false;
            }
        }

        let mut file_combined_size: i32 = 0;
        for m in &self.parts {
            // FIXME: duplicate code, see transaction.
            //        we need a helper function for this.
            if m.name.is_empty() {
                continue;
            }
            let offset = t.vars.offset + 1;

            if m.type_ == PartType::File {
                if let Some(f) = &m.tmp_file
                    && !f.get_filename().is_empty()
                {
                    let n = f.get_filename().as_bytes();
                    t.vars.files_tmp_names.set(n, n, m.filename_offset);
                }

                // filename* takes precedence over filename, so we set the
                // variable accordingly
                if !m.filename_star.is_empty() {
                    t.vars.files.set(&m.name, &m.filename_star, m.filename_star_offset);
                } else if !m.filename.is_empty() {
                    t.vars.files.set(&m.name, &m.filename, m.filename_offset);
                }

                t.vars.files_names.set(&m.name, &m.name, m.name_offset);

                t.vars.files_sizes.set_with_len(
                    &m.name,
                    m.tmp_file_size.0.to_string().as_bytes(),
                    m.tmp_file_size.1,
                    m.tmp_file_size.0,
                );

                t.vars.files_tmp_content.set(&m.name, &m.value, m.value_offset);

                // int + size_t, stored back into an int
                file_combined_size = (file_combined_size as usize).wrapping_add(m.tmp_file_size.0) as i32;

                t.vars.files_combined_size.set_with_len(
                    file_combined_size.to_string().as_bytes(),
                    m.tmp_file_size.1,
                    m.tmp_file_size.0,
                );
            } else {
                crate::ms_dbg_a!(
                    t,
                    4,
                    "Adding request argument (BODY): name \"{}\", value \"{}\"",
                    lossy(&m.name),
                    lossy(&m.value)
                );
                t.vars.args.set(&m.name, &m.value, offset.wrapping_add(m.value_offset));
                t.vars.args_post.set(&m.name, &m.value, offset.wrapping_add(m.value_offset));
            }
        }

        true
    }

    /// `init`: validates the Content-Type header and extracts the boundary.
    pub fn init(&mut self, t: &mut Transaction<'_>) -> bool {
        self.upload_keep_files = t.rules.properties.upload_keep_files;
        self.bufleft = MULTIPART_BUF_SIZE;
        self.bufptr = 0;
        self.buf_contains_line = true;
        self.mpp = None;

        if self.header.is_empty() {
            self.flag_error = 1;
            crate::ms_dbg_a!(t, 4, "Multipart: Content-Type header not available.");
            self.error = Some("Multipart: Content-Type header not available.".to_string());
            return false;
        }

        if self.header.len() > 1024 {
            self.flag_error = 1;
            crate::ms_dbg_a!(t, 4, "Multipart: Invalid boundary in C-T (length).");
            self.error = Some("Multipart: Invalid boundary in C-T (length).".to_string());
            return false;
        }

        // The checks below work on the header as a C string.
        let header = c_str(&self.header).to_vec();

        if header.len() < 19 || !header[..19].eq_ignore_ascii_case(b"multipart/form-data") {
            self.flag_error = 1;
            crate::ms_dbg_a!(t, 4, "Multipart: Invalid MIME type.");
            self.error = Some("Multipart: Invalid MIME type.".to_string());
            return false;
        }

        // Count how many times the word "boundary" appears in the C-T
        // header.
        if Self::count_boundary_params(&header) > 1 {
            self.flag_error = 1;
            crate::ms_dbg_a!(t, 4, "Multipart: Multiple boundary parameters in C-T.");
            self.error = Some("Multipart: Multiple boundary parameters in C-T.".to_string());
            return false;
        }

        if let Some(boundary_tmp) = find(&header, b"boundary") {
            let mut seen_semicolon = false;

            // Check for extra characters before the boundary.
            for &c in &header[19..boundary_tmp] {
                if !is_space(c) {
                    if !seen_semicolon && c == b';' {
                        seen_semicolon = true; // It is OK to have one semicolon.
                    } else {
                        self.flag_error = 1;
                        crate::ms_dbg_a!(t, 4, "Multipart: Invalid boundary in C-T (malformed).");
                        self.error = Some("Multipart: Invalid boundary in C-T (malformed).".to_string());
                        return false;
                    }
                }
            }

            // Have we seen the semicolon in the header?
            if !seen_semicolon {
                self.flag_missing_semicolon = 1;
            }

            let Some(eq) = header[boundary_tmp + 8..].iter().position(|&c| c == b'=') else {
                self.flag_error = 1;
                crate::ms_dbg_a!(t, 4, "Multipart: Invalid boundary in C-T (malformed).");
                self.error = Some("Multipart: Invalid boundary in C-T (malformed).".to_string());
                return false;
            };
            let b = boundary_tmp + 8 + eq;

            // Check parameter name ends well: all characters between the end
            // of the boundary and the = character. (The C++ code guarded
            // this loop with a pointer comparison between two different
            // strings, which is always true.)
            for &c in &header[boundary_tmp + 8..b] {
                if is_space(c) {
                    // Flag for whitespace after parameter name.
                    self.flag_boundary_whitespace = 1;
                } else {
                    self.flag_error = 1;
                    crate::ms_dbg_a!(t, 4, "Multipart: Invalid boundary in C-T (parameter name).");
                    self.error = Some("Multipart: Invalid boundary in C-T (parameter name).".to_string());
                    return false;
                }
            }

            // Go over the = character.
            let bv = &header[b + 1..];
            let len = bv.len();

            // Flag for whitespace before parameter value.
            if is_space(c_at(bv, 0)) {
                self.flag_boundary_whitespace = 1;
            }

            // Is the boundary quoted?
            if len >= 2 && bv[0] == b'"' && bv[len - 1] == b'"' {
                // Quoted.
                self.boundary = bv[1..len - 1].to_vec();
                if self.boundary.is_empty() {
                    return false;
                }
                self.flag_boundary_quoted = 1;
            } else {
                // Not quoted.

                // Test for partial quoting.
                if c_at(bv, 0) == b'"' || (len >= 2 && bv[len - 1] == b'"') {
                    self.flag_error = 1;
                    crate::ms_dbg_a!(t, 4, "Multipart: Invalid boundary in C-T (quote).");
                    self.error = Some("Multipart: Invalid boundary in C-T (quote).".to_string());
                    return false;
                }

                self.boundary = bv.to_vec();
                if self.boundary.is_empty() {
                    return false;
                }

                self.flag_boundary_quoted = 0;
            }

            // Case-insensitive test for the string "boundary" in the
            // boundary.
            if Self::count_boundary_params(&self.boundary) != 0 {
                self.flag_error = 1;
                crate::ms_dbg_a!(t, 4, "Multipart: Invalid boundary in C-T (content).");
                self.error = Some("Multipart: Invalid boundary in C-T (content).".to_string());
                return false;
            }

            // Some frameworks are known to incorrectly include a charset=
            // parameter after the boundary. Doing so is not RFC-compliant,
            // but we will tolerate it.
            if !Self::boundary_characters_valid(&self.boundary)
                && let Some(semicolon_after_boundary) = self.boundary.iter().position(|&c| c == b';')
            {
                crate::ms_dbg_a!(t, 3, "Multipart: Invalid parameter after boundary in C-T (tolerated).");
                self.boundary.truncate(semicolon_after_boundary);
            }
            // Validate the characters used in the boundary.
            if !Self::boundary_characters_valid(&self.boundary) {
                self.flag_error = 1;
                crate::ms_dbg_a!(t, 4, "Multipart: Invalid boundary in C-T (characters).");
                self.error = Some("Multipart: Invalid boundary in C-T (characters).".to_string());
                return false;
            }

            crate::ms_dbg_a!(
                t,
                9,
                "Multipart: Boundary{}: {}",
                if self.flag_boundary_quoted != 0 { " (quoted)" } else { "" },
                lossy(&self.boundary)
            );

            if self.boundary.is_empty() {
                self.flag_error = 1;
                crate::ms_dbg_a!(t, 4, "Multipart: Invalid boundary in C-T (empty).");
                self.error = Some("Multipart: Invalid boundary in C-T (empty).".to_string());
                return false;
            }
        } else {
            // Could not find boundary in the C-T header.
            self.flag_error = 1;

            // Test for case-insensitive boundary. Allowed by the RFC but
            // highly unusual.
            if Self::count_boundary_params(&header) > 0 {
                crate::ms_dbg_a!(t, 4, "Multipart: Invalid boundary in C-T (case sensitivity).");
                self.error = Some("Multipart: Invalid boundary in C-T (case sensitivity).".to_string());
                return false;
            }

            crate::ms_dbg_a!(t, 4, "Multipart: Boundary not found in C-T.");
            self.error = Some("Multipart: Boundary not found in C-T.".to_string());
            return false;
        }

        true
    }

    /// `process`: assumes that all data is in `data` (we are not processing
    /// chunks); `offset` is where the body starts.
    pub fn process(&mut self, t: &mut Transaction<'_>, data: &[u8], offset: usize) -> bool {
        let mut inptr = 0usize;
        let mut inleft = data.len();
        let mut z: usize = 0;

        if data.is_empty() {
            return true;
        }
        self.seen_data = true;

        if self.is_complete {
            self.flag_data_before = 1;

            crate::ms_dbg_a!(t, 4, "Multipart: Ignoring data after last boundary (received {} bytes)", data.len());

            return true;
        }

        if self.bufleft == 0 {
            self.flag_error = 1;
            crate::ms_dbg_a!(t, 4, "Multipart: Internal error in process_chunk: no space left in the buffer");
            return false;
        }

        // here we loop through the available data, one byte at a time
        while inleft > 0 {
            let c = data[inptr];
            let mut process_buffer = false;

            z += 1;

            if c == b'\r' && self.bufleft == 1 {
                // we don't want to take \r as the last byte in the buffer
                process_buffer = true;
            } else {
                inptr += 1;
                inleft -= 1;

                self.buf[self.bufptr] = c;
                self.bufptr += 1;
                self.bufleft -= 1;
            }

            // until we either reach the end of the line or the end of our
            // internal buffer
            if c == b'\n' || self.bufleft == 0 || process_buffer {
                let mut processed_as_boundary = false;

                self.buf[self.bufptr] = 0;
                let blen = self.boundary.len();
                let buf_strlen = c_str(&self.buf).len();

                // Do we have something that looks like a boundary?
                if self.buf_contains_line && buf_strlen > 3 && self.buf[0] == b'-' && self.buf[1] == b'-' {
                    // Does it match our boundary?
                    if buf_strlen >= blen + 2 && c_starts_with(&self.buf, 2, &self.boundary) {
                        if self.crlf_state_buf_end == 2 {
                            self.flag_lf_line = 1;
                        }
                        if self.mpp_substate_part_data_read == 0 && self.boundary_count > 0 {
                            // string matches our boundary, but it's where
                            // part data should begin
                            self.flag_invalid_part = 1;
                            crate::ms_dbg_a!(t, 3, "Multipart: Invalid part (data contains boundary)");
                        } else {
                            let mut boundary_end = 2 + blen;
                            // if it match, AND there was a matched boundary
                            // at least, set the flag_unmatched_boundary flag
                            // to 2; this indicates that there were an opened
                            // boundary, which matches the reference, and here
                            // is the final boundary. The flag will differ
                            // from 0, so the previous rules ("!@eq 0") will
                            // catch all "errors", without any modification,
                            // but we can use the new, permission mode with
                            // "@eq 1"
                            if self.boundary_count > 0 {
                                self.flag_unmatched_boundary = 2;
                            }
                            let mut is_final = false;
                            let at = |i: usize| c_at(&self.buf, i);

                            // Is this the final boundary?
                            if at(boundary_end) == b'-' && at(boundary_end + 1) == b'-' {
                                is_final = true;
                                boundary_end += 2;

                                if self.is_complete {
                                    self.flag_error = 1;
                                    crate::ms_dbg_a!(t, 4, "Multipart: Invalid boundary (final duplicate).");
                                    self.error = Some("Multipart: Invalid boundary (final duplicate).".to_string());
                                    return false;
                                }
                            }

                            // Allow for CRLF and LF line endings.
                            if (at(boundary_end) == b'\r' && at(boundary_end + 1) == b'\n' && at(boundary_end + 2) == 0)
                                || (at(boundary_end) == b'\n' && at(boundary_end + 1) == 0)
                            {
                                if at(boundary_end) == b'\n' {
                                    self.flag_lf_line = 1;
                                } else {
                                    self.flag_crlf_line = 1;
                                }

                                if self.process_boundary(t, is_final) < 0 {
                                    self.flag_error = 1;
                                    return false;
                                }

                                if is_final {
                                    self.is_complete = true;
                                }

                                processed_as_boundary = true;
                                self.boundary_count += 1;
                            } else {
                                // error
                                self.flag_error = 1;
                                let line = lossy(c_str(&self.buf)).into_owned();
                                crate::ms_dbg_a!(t, 4, "Multipart: Invalid boundary: {}", line);
                                self.error = Some(format!("Multipart: Invalid boundary: {}", line));
                                return false;
                            }
                        }
                    } else {
                        // It looks like a boundary but we couldn't match it.

                        // Check if an attempt to use quotes around the
                        // boundary was made.
                        if self.flag_boundary_quoted != 0
                            && buf_strlen >= blen + 3
                            && self.buf[2] == b'"'
                            && c_starts_with(&self.buf, 3, &self.boundary)
                        {
                            self.flag_error = 1;
                            crate::ms_dbg_a!(t, 4, "Multipart: Invalid boundary (quotes).");
                            self.error = Some("Multipart: Invalid boundary (quotes).".to_string());
                            return false;
                        }

                        // Check the beginning of the boundary for whitespace.
                        let mut p = 2;
                        while is_space(c_at(&self.buf, p)) {
                            p += 1;
                        }

                        if p != 2 && c_starts_with(&self.buf, p, &self.boundary) {
                            // Found whitespace in front of a boundary.
                            self.flag_error = 1;
                            crate::ms_dbg_a!(t, 4, "Multipart: Invalid boundary (whitespace).");
                            self.error = Some("Multipart: Invalid boundary (whitespace).".to_string());
                            return false;
                        }

                        self.flag_unmatched_boundary = 1;
                    }
                } else if self.buf_contains_line {
                    // We do not think the buffer contains a boundary. Look
                    // into the buffer to see if there's anything there that
                    // resembles a boundary.
                    let len = MULTIPART_BUF_SIZE - self.bufleft;
                    let p = &self.buf;
                    for i in 0..len {
                        if p[i] == b'-' && i + 1 < len && p[i + 1] == b'-' && c_starts_with(p, i + 2, &self.boundary) {
                            self.flag_unmatched_boundary = 1;
                            break;
                        }
                    }
                }

                // Process as data if it was not a boundary.
                if !processed_as_boundary {
                    if self.mpp.is_none() {
                        self.flag_data_before = 1;
                        crate::ms_dbg_a!(t, 4, "Multipart: Ignoring data before first boundary.");
                    } else if self.mpp_state == 0 {
                        if self.bufleft == 0 || process_buffer {
                            // part header lines must be shorter than
                            // MULTIPART_BUF_SIZE bytes
                            self.flag_error = 1;
                            crate::ms_dbg_a!(
                                t,
                                4,
                                "Multipart: Part header line over {} bytes long",
                                MULTIPART_BUF_SIZE
                            );
                            self.error =
                                Some(format!("Multipart: Part header line over {} bytes long", MULTIPART_BUF_SIZE));
                            return false;
                        }

                        // Like C++, a failing part header records its error
                        // but does not stop the processing.
                        self.process_part_header(t, offset.wrapping_add(z));
                    } else if !self.process_part_data(t, offset.wrapping_add(z)) {
                        self.flag_error = 1;
                        return false;
                    }
                }

                // Update the offset of the data we are about to process.
                // This is to allow us to know the offsets of individual
                // files and variables.
                self.buf_offset = self.buf_offset.wrapping_add((MULTIPART_BUF_SIZE - self.bufleft) as u32);

                // reset the pointer to the beginning of the buffer and
                // continue to accept input data
                self.bufptr = 0;
                self.bufleft = MULTIPART_BUF_SIZE;
                self.buf_contains_line = c == b'\n';

                if c == b'\n' {
                    if self.crlf_state == 1 {
                        self.crlf_state = 3;
                    } else {
                        self.crlf_state = 2;
                    }
                }
                self.crlf_state_buf_end = self.crlf_state;
            }

            if c == b'\r' {
                self.crlf_state = 1;
            } else if c != b'\n' {
                self.crlf_state = 0;
            }

            if self.is_complete && inleft != 0 {
                self.flag_data_after = 1;
                crate::ms_dbg_a!(t, 4, "Multipart: Ignoring data after last boundary ({}bytes left)", inleft);
                return true;
            }
        }

        true
    }

    /// The C++ destructor: marks the temporary files of the parts for
    /// deletion (unless `SecUploadKeepFiles` is on); they stay on disk until
    /// the transaction is done with them.
    fn cleanup(&mut self, t: Option<&Transaction<'_>>) {
        if self.cleaned_up {
            return;
        }
        self.cleaned_up = true;
        crate::ms_dbg_opt!(
            t,
            4,
            "Multipart: Cleanup started (keep files set to {})",
            config_boolean_string(self.upload_keep_files)
        );

        if self.upload_keep_files != Some(true) {
            for m in &self.parts {
                if m.type_ == PartType::File
                    && let Some(f) = &m.tmp_file
                {
                    // only mark for deletion for now; the file should stay
                    // on disk until the transaction is complete
                    crate::ms_dbg_opt!(t, 9, "Multipart: Marking temporary file for deletion: {}", f.get_filename());
                    f.set_delete();
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

/// Helpers shared by the request body processor tests: a transaction set up
/// as the regression test harness does, with a debug log kept in memory.
#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::Mutex;

    use crate::debug_log::debug_log::DebugLog;
    use crate::modsecurity::ModSecurity;
    use crate::rules_set::RulesSet;
    use crate::rules_set_properties::RulesSetProperties;
    use crate::transaction::{RequestBodyType, Transaction};

    /// A debug log keeping the messages in memory.
    #[derive(Debug, Default)]
    pub struct CaptureLog {
        pub lines: Mutex<Vec<String>>,
    }

    impl DebugLog for CaptureLog {
        fn write(&self, _level: i32, msg: &str) {
            self.lines.lock().unwrap().push(msg.to_string());
        }
        fn write_ctx(&self, _level: i32, _id: &str, _uri: &str, msg: &str) {
            self.lines.lock().unwrap().push(msg.to_string());
        }
        fn is_log_file_set(&self) -> bool {
            false
        }
        fn is_log_level_set(&self) -> bool {
            true
        }
        fn set_debug_log_level(&mut self, _level: i32) {}
        fn set_debug_log_file(&mut self, _file_name: &str) -> Result<(), String> {
            Ok(())
        }
        fn get_debug_log_file(&self) -> &str {
            ""
        }
        fn get_debug_log_level(&self) -> i32 {
            9
        }
        fn debug_level(&self) -> i32 {
            9
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    /// A rule set with an in-memory debug log at level 9.
    pub fn new_rules() -> RulesSet {
        let mut rules = RulesSet::new();
        rules.properties = RulesSetProperties::with_debug_log(Box::new(CaptureLog::default()));
        rules
    }

    /// The messages logged so far.
    pub fn log(rules: &RulesSet) -> Vec<String> {
        let l = rules.properties.debug_log.as_any().downcast_ref::<CaptureLog>().unwrap();
        l.lines.lock().unwrap().clone()
    }

    /// Runs a request with `headers` and `body` up to (and including) the
    /// request body phase; `processor` mimics `ctl:requestBodyProcessor`.
    pub fn run<'a>(
        ms: &'a ModSecurity,
        rules: &'a RulesSet,
        headers: &[(&[u8], &[u8])],
        body: &[u8],
        processor: Option<RequestBodyType>,
    ) -> Transaction<'a> {
        let mut t = Transaction::new(ms, rules, None);
        t.process_connection("200.249.12.31", 123, "200.249.12.31", 80);
        t.process_uri(b"/", b"POST", b"1.1");
        for (k, v) in headers {
            t.add_request_header(k, v);
        }
        t.process_request_headers();
        if let Some(p) = processor {
            t.request_body_processor = p;
        }
        t.append_request_body(body);
        t.process_request_body();
        t
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{log, new_rules, run};
    use super::*;
    use crate::modsecurity::ModSecurity;

    fn ct(boundary: &str) -> Vec<u8> {
        format!("multipart/form-data; boundary={}", boundary).into_bytes()
    }

    const NORMAL: &[u8] = b"--0000\r\n\
Content-Disposition: form-data; name=\"name\"\r\n\
\r\n\
Brian Rectanus\r\n\
--0000\r\n\
Content-Disposition: form-data; name=\"email\"\r\n\
\r\n\
brian.rectanus@breach.com\r\n\
--0000\r\n\
Content-Disposition: form-data; name=\"image\"; filename=\"image.jpg\"\r\n\
Content-Type: image/jpeg\r\n\
\r\n\
BINARYDATA\r\n\
--0000--\r\n";

    #[test]
    fn normal_request() {
        let ms = ModSecurity::new();
        let rules = new_rules();
        let ct = ct("0000");
        let t = run(&ms, &rules, &[(b"Content-Type", &ct)], NORMAL, None);
        assert_eq!(t.vars.args.resolve_first(b"name").unwrap(), b"Brian Rectanus");
        assert_eq!(t.vars.args_post.resolve_first(b"email").unwrap(), b"brian.rectanus@breach.com");
        assert_eq!(t.vars.files.resolve_first(b"image").unwrap(), b"image.jpg");
        assert_eq!(t.vars.files_sizes.resolve_first(b"image").unwrap(), b"10");
        assert_eq!(t.vars.files_names.resolve_first(b"image").unwrap(), b"image");
        assert_eq!(t.vars.multipart_strict_error.value, b"0");
        // 2: boundaries were seen and the final one matched
        assert_eq!(t.vars.multipart_unmatched_boundary.value, b"2");
        assert_eq!(t.vars.reqbody_error.value, b"0");
        let l = log(&rules);
        assert!(l.iter().any(|m| m
            == "Multipart: Added file part to the list: name \"image\" file name \"image.jpg\" (offset 258, length 10)"));
        assert!(l.iter().any(|m| m == "Multipart: Cleanup started (keep files set to Not set)"));
    }

    #[test]
    fn final_boundary_missing() {
        let ms = ModSecurity::new();
        let rules = new_rules();
        let ct = ct("0000");
        let body = b"--0000\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nb\r\n";
        let t = run(&ms, &rules, &[(b"Content-Type", &ct)], body, None);
        assert_eq!(t.vars.reqbody_error.value, b"1");
        assert_eq!(t.vars.reqbody_error_msg.value, b"Multipart parsing error: Multipart: Final boundary missing.");
    }

    #[test]
    fn invalid_boundaries() {
        let cases: &[(&[u8], &str)] = &[
            (b"multipart/form-data", "Multipart: Boundary not found in C-T."),
            (b"multipart/form-data; BOUNDARY=a", "Multipart: Invalid boundary in C-T (case sensitivity)."),
            (b"multipart/form-data; boundary=a; boundary=b", "Multipart: Multiple boundary parameters in C-T."),
            (b"multipart/form-data; boundary=\"a", "Multipart: Invalid boundary in C-T (quote)."),
            (b"multipart/form-data; boundary=a\"", "Multipart: Invalid boundary in C-T (quote)."),
            (b"multipart/form-data, boundary=a", "Multipart: Invalid boundary in C-T (malformed)."),
            (b"multipart/form-data; boundaryx=a", "Multipart: Invalid boundary in C-T (parameter name)."),
            (b"multipart/form-data; boundary=a\x01", "Multipart: Invalid boundary in C-T (characters)."),
        ];
        for (header, err) in cases {
            let ms = ModSecurity::new();
            let rules = new_rules();
            let t = run(&ms, &rules, &[(b"Content-Type", header)], b"--a\r\n", None);
            assert_eq!(
                String::from_utf8_lossy(&t.vars.reqbody_error_msg.value),
                format!("Multipart parsing error: {}", err),
                "{}",
                String::from_utf8_lossy(header)
            );
        }
    }

    #[test]
    fn tolerated_parameter_after_boundary_and_flags() {
        let ms = ModSecurity::new();
        let rules = new_rules();
        let header = b"multipart/form-data boundary = \"0000\"; charset=utf-8";
        // the value ` "0000"; charset=utf-8` is not quoted; cut at the `;` it
        // still has invalid characters
        let t = run(&ms, &rules, &[(b"Content-Type", header)], NORMAL, None);
        assert_eq!(
            t.vars.reqbody_error_msg.value,
            b"Multipart parsing error: Multipart: Invalid boundary in C-T (characters)."
        );

        let ms = ModSecurity::new();
        let rules = new_rules();
        let header = b"multipart/form-data boundary =0000;charset=utf-8";
        let t = run(&ms, &rules, &[(b"Content-Type", header)], NORMAL, None);
        assert_eq!(t.vars.reqbody_error.value, b"0");
        assert_eq!(t.vars.multipart_missing_semicolon.value, b"1");
        assert_eq!(t.vars.multipart_boundary_white_space.value, b"1");
        assert_eq!(t.vars.multipart_strict_error.value, b"1");
        assert!(log(&rules).iter().any(|m| m == "Multipart: Invalid parameter after boundary in C-T (tolerated)."));
    }

    #[test]
    fn content_disposition_parsing() {
        let ms = ModSecurity::new();
        let rules = new_rules();
        let ct = ct("0000");
        let body = b"--0000\r\n\
Content-Disposition: form-data; name='a'; filename*=utf-8'en'na%20me.txt\r\n\
\r\n\
x\r\n\
--0000\r\n\
Content-Disposition: form-data;\r\n\
\x20name=\"b\\\"c\"\r\n\
\r\n\
y\r\n\
--0000--\r\n";
        let t = run(&ms, &rules, &[(b"Content-Type", &ct)], body, None);
        assert_eq!(t.vars.reqbody_error.value, b"0", "{:?}", log(&rules));
        assert_eq!(t.vars.files.resolve_first(b"a").unwrap(), b"na me.txt");
        assert_eq!(t.vars.multipart_file_name_charset.resolve_first(b"a").unwrap(), b"utf-8");
        assert_eq!(t.vars.multipart_file_name_language.resolve_first(b"a").unwrap(), b"en");
        assert_eq!(t.vars.multipart_invalid_quoting.value, b"1");
        assert_eq!(t.vars.multipart_header_folding.value, b"1");
        assert_eq!(t.vars.args.resolve_first(b"b\"c").unwrap(), b"y");
        // the part headers, recorded per part name
        let mut l = Vec::new();
        t.vars.multipart_part_headers.resolve(&mut l);
        let headers: Vec<_> = l.iter().map(|v| String::from_utf8_lossy(v.value()).into_owned()).collect();
        assert!(headers.contains(&"Content-Disposition: form-data; name=\"b\\\"c\"".to_string()), "{:?}", headers);
    }

    #[test]
    fn header_errors_do_not_stop_parsing() {
        // As in C++: process_part_header failures return 0, which is not
        // treated as fatal; only the error is recorded.
        let ms = ModSecurity::new();
        let rules = new_rules();
        let ct = ct("0000");
        let body = b"--0000\r\nContent-Type: text/plain\r\n\r\nx\r\n--0000--\r\n";
        let t = run(&ms, &rules, &[(b"Content-Type", &ct)], body, None);
        let l = log(&rules);
        assert!(l.iter().any(|m| m == "Multipart: Part missing Content-Disposition header."));
        // the part stays in the header state: "x" is a header line without
        // colon, and the final boundary, where data should begin, too
        assert!(l.iter().any(|m| m == "Multipart: Invalid part header (colon missing): x\r\n"));
        assert!(l.iter().any(|m| m == "Multipart: Invalid part (data contains boundary)"));
        assert_eq!(t.vars.reqbody_error_msg.value, b"Multipart parsing error: Multipart: Final boundary missing.");
        assert_eq!(t.vars.multipart_invalid_part.value, b"1");
    }

    #[test]
    fn data_before_and_after() {
        let ms = ModSecurity::new();
        let rules = new_rules();
        let ct = ct("0000");
        let body = b"junk\r\n--0000\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nb\r\n--0000--\r\nafter";
        let t = run(&ms, &rules, &[(b"Content-Type", &ct)], body, None);
        assert_eq!(t.vars.multipart_data_before.value, b"1");
        assert_eq!(t.vars.multipart_data_after.value, b"1");
        assert_eq!(t.vars.args.resolve_first(b"a").unwrap(), b"b");
        let l = log(&rules);
        assert!(l.iter().any(|m| m == "Multipart: Ignoring data after last boundary (5bytes left)"));
    }

    #[test]
    fn lf_line_endings_and_unmatched_boundary() {
        let ms = ModSecurity::new();
        let rules = new_rules();
        let ct = ct("0000");
        let body = b"--0000\nContent-Disposition: form-data; name=\"a\"\n\nb --0000x\n--0000--\n";
        let t = run(&ms, &rules, &[(b"Content-Type", &ct)], body, None);
        assert_eq!(t.vars.multipart_lf_line.value, b"1");
        assert_eq!(t.vars.multipart_crlf_lf_lines.value, b"0");
        assert_eq!(t.vars.multipart_unmatched_boundary.value, b"2");
        assert_eq!(t.vars.args.resolve_first(b"a").unwrap(), b"b --0000x");
    }

    #[test]
    fn upload_files_are_saved_and_deleted() {
        let dir = std::env::temp_dir().join(format!("msrs-multipart-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ms = ModSecurity::new();
        let mut rules = new_rules();
        rules.properties.tmp_save_uploaded_files = Some(true);
        rules.properties.upload_directory = Some(dir.to_string_lossy().into_owned());
        rules.properties.upload_file_mode = Some(0o600);
        let ct = ct("0000");
        let name;
        {
            let t = run(&ms, &rules, &[(b"Content-Type", &ct)], NORMAL, None);
            name = String::from_utf8(t.vars.files_tmp_names.iter().next().unwrap().0.to_vec()).unwrap();
            assert!(name.starts_with(rules.properties.upload_directory.as_deref().unwrap()), "{}", name);
            assert!(name.contains("-file-"));
            assert_eq!(std::fs::read(&name).unwrap(), b"BINARYDATA");
            assert_eq!(t.vars.files_tmp_content.resolve_first(b"image").unwrap(), b"BINARYDATA");
            assert_eq!(t.vars.files_combined_size.value, b"10");
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&name).unwrap().permissions().mode() & 0o777, 0o600);
            let l = log(&rules);
            assert!(l.iter().any(|m| m.starts_with("Multipart: Created temporary file 1 (mode 0600): ")), "{:?}", l);
            assert!(l.iter().any(|m| m.starts_with("Multipart: Marking temporary file for deletion: ")));
        }
        // gone with the transaction
        assert!(!std::path::Path::new(&name).exists());

        // SecUploadKeepFiles On keeps them
        rules.properties.upload_keep_files = Some(true);
        let name;
        {
            let t = run(&ms, &rules, &[(b"Content-Type", &ct)], NORMAL, None);
            name = String::from_utf8(t.vars.files_tmp_names.iter().next().unwrap().0.to_vec()).unwrap();
        }
        assert!(std::path::Path::new(&name).exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn upload_file_limit() {
        let dir = std::env::temp_dir().join(format!("msrs-multipart-limit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ms = ModSecurity::new();
        let mut rules = new_rules();
        rules.properties.tmp_save_uploaded_files = Some(true);
        rules.properties.upload_directory = Some(dir.to_string_lossy().into_owned());
        rules.properties.upload_file_limit = Some(1);
        let ct = ct("0000");
        let body = b"--0000\r\n\
Content-Disposition: form-data; name=\"f1\"; filename=\"1.txt\"\r\n\r\none\r\n\
--0000\r\n\
Content-Disposition: form-data; name=\"f2\"; filename=\"2.txt\"\r\n\r\ntwo!\r\n\
--0000--\r\n";
        let t = run(&ms, &rules, &[(b"Content-Type", &ct)], body, None);
        assert_eq!(
            t.vars.reqbody_error_msg.value,
            b"Multipart parsing error: Multipart: Upload file limit exceeded 1. Use SecUploadFileLimit to change the limit."
        );
        assert_eq!(t.vars.files_sizes.resolve_first(b"f2").unwrap(), b"4");
        assert_eq!(t.vars.files_tmp_names.len(), 1);
        assert_eq!(t.vars.multipart_strict_error.value, b"1");
        drop(t);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn helpers() {
        assert_eq!(Multipart::count_boundary_params(b"a; BOUNDARY=1; boundary"), 1);
        assert_eq!(Multipart::count_boundary_params(b"boundary=1 boundary=2"), 2);
        assert!(Multipart::boundary_characters_valid(b"a b"));
        assert!(!Multipart::boundary_characters_valid(b"a "));
        assert!(!Multipart::boundary_characters_valid(b"a;b"));
        assert!(Multipart::is_token_char(b'a'));
        assert!(!Multipart::is_token_char(b'='));
        assert!(c_starts_with(b"--ab\0", 2, b"ab"));
        assert!(!c_starts_with(b"--a\0b", 2, b"ab"));
    }
}

/// Differential harness: runs the requests of regression test files through
/// the request body processors and prints the related debug log messages,
/// for comparison with the C++ implementation. Run with
/// `BODYPROC_REGRESSION=<file.json>[,...] cargo test --lib regression_dump -- --ignored --nocapture`.
#[cfg(test)]
mod regression_dump {
    use super::test_support::{CaptureLog, log};
    use crate::modsecurity::ModSecurity;
    use crate::rules_set::RulesSet;
    use crate::rules_set_properties::{ParseXmlIntoArgs, RulesSetProperties, parse_config_number, parse_octal_mode};
    use crate::transaction::{RequestBodyType, Transaction};
    use crate::utils::json::{JsonValue, parse_tree};

    const PREFIXES: &[&str] = &[
        "Multipart",
        "Adding request argument",
        "Skipping request argument",
        "XML",
        "JSON",
        "Request body excluding files",
        "Registered XML",
        "Failed to register",
    ];

    fn s(v: Option<&JsonValue>) -> Vec<u8> {
        match v {
            Some(JsonValue::String(s)) => s.clone(),
            Some(JsonValue::Number(n)) => n.clone(),
            _ => Vec::new(),
        }
    }

    fn configure(rules: &mut RulesSet, lines: &[String]) -> (Option<RequestBodyType>, Option<ParseXmlIntoArgs>) {
        let p = &mut rules.properties;
        let mut processor = None;
        let mut ctl_args = None;
        for l in lines {
            let mut it = l.splitn(2, ' ');
            let d = it.next().unwrap_or("").to_ascii_lowercase();
            let v = it.next().unwrap_or("").trim().trim_matches('"').to_string();
            let b = |v: &str| {
                if v.eq_ignore_ascii_case("on") { Some(true) } else { Some(false) }
            };
            match d.as_str() {
                "secrequestbodyjsondepthlimit" => {
                    p.request_body_json_depth_limit = Some(parse_config_number(&v).unwrap())
                }
                "secargumentslimit" => p.arguments_limit = Some(parse_config_number(&v).unwrap()),
                "secrequestbodynofileslimit" => p.request_body_no_files_limit = Some(parse_config_number(&v).unwrap()),
                "secrequestbodylimit" => p.request_body_limit = Some(parse_config_number(&v).unwrap()),
                "secuploadfilelimit" => p.upload_file_limit = Some(parse_config_number(&v).unwrap()),
                "secuploadfilemode" => p.upload_file_mode = Some(parse_octal_mode(&v).unwrap()),
                "secuploaddir" => p.upload_directory = Some(v.clone()),
                "secuploadkeepfiles" => p.upload_keep_files = b(&v),
                "sectmpsaveuploadedfiles" => p.tmp_save_uploaded_files = b(&v),
                "secxmlexternalentity" => p.sec_xml_external_entity = b(&v),
                "secparsexmlintoargs" => {
                    p.sec_xml_parse_xml_into_args = match v.to_ascii_lowercase().as_str() {
                        "on" => Some(ParseXmlIntoArgs::On),
                        "onlyargs" => Some(ParseXmlIntoArgs::OnlyArgs),
                        _ => Some(ParseXmlIntoArgs::Off),
                    }
                }
                "secrule" => {
                    if l.contains("ctl:requestBodyProcessor=XML") {
                        processor = Some(RequestBodyType::XMLRequestBody);
                    } else if l.contains("ctl:requestBodyProcessor=JSON") {
                        processor = Some(RequestBodyType::JSONRequestBody);
                    }
                    if l.contains("ctl:parseXmlIntoArgs=OnlyArgs") {
                        ctl_args = Some(ParseXmlIntoArgs::OnlyArgs);
                    } else if l.contains("ctl:parseXmlIntoArgs=On") {
                        ctl_args = Some(ParseXmlIntoArgs::On);
                    } else if l.contains("ctl:parseXmlIntoArgs=Off") {
                        ctl_args = Some(ParseXmlIntoArgs::Off);
                    }
                }
                _ => {}
            }
        }
        (processor, ctl_args)
    }

    /// Emulates the `SecRule XML...` rules of a test: XPath targets (with
    /// the rule's `xmlns` actions) and the validation operators.
    #[cfg(feature = "libxml2")]
    fn xml_rules(t: &mut Transaction<'_>, lines: &[String]) {
        use crate::actions::xmlns::XmlNS;
        use crate::operators::operator::Operator;
        use crate::rule_with_actions::{RuleWithActions, RuleWithActionsKind};
        use crate::run_time_string::RunTimeString;
        use crate::variables::variable::Variable;

        for l in lines {
            let Some(rest) = l.strip_prefix("SecRule XML") else {
                continue;
            };
            let target = format!("XML{}", rest.split(' ').next().unwrap_or(""));
            let quoted: Vec<&str> = l.split('"').collect();
            let op = quoted.get(1).copied().unwrap_or("");
            let actions = quoted.get(3).copied().unwrap_or("");
            let mut acts: Vec<crate::rule_with_actions::RuleAction> = Vec::new();
            for a in actions.split(',') {
                if a.starts_with("xmlns:") {
                    let x = XmlNS::new(a).unwrap();
                    acts.push(crate::rule_with_actions::RuleAction::Other(Box::new(x)));
                }
            }
            let rule = RuleWithActions::new(Some(acts), None, "x", 1, RuleWithActionsKind::Unconditional);
            if target != "XML" {
                let v = crate::variables::xml::Xml::new(&target);
                let mut values = Vec::new();
                v.evaluate(t, Some(&rule), &mut values);
                for x in values {
                    println!("XMLVAR {}={}", String::from_utf8_lossy(x.key()), String::from_utf8_lossy(x.value()));
                }
            }
            let (name, param) = op.split_once(' ').unwrap_or((op, ""));
            let mut o: Box<dyn Operator> = match name {
                "@validateDTD" => {
                    Box::new(crate::operators::validate_dtd::ValidateDTD::new(RunTimeString::from_text(param)))
                }
                "@validateSchema" => {
                    Box::new(crate::operators::validate_schema::ValidateSchema::new(RunTimeString::from_text(param)))
                }
                _ => continue,
            };
            o.init("x.json").unwrap();
            let mut rm = crate::rule_message::RuleMessage::new(&rule);
            println!("OP {} -> {}", name, o.evaluate(t, &rule, b"", &mut rm));
        }
    }

    #[test]
    #[ignore]
    fn regression_dump() {
        let Ok(files) = std::env::var("BODYPROC_REGRESSION") else {
            return;
        };
        // resources are relative to the test directory
        if let Ok(dir) = std::env::var("BODYPROC_CWD") {
            std::env::set_current_dir(dir).unwrap();
        }
        for f in files.split(',') {
            let data = std::fs::read(f).unwrap();
            let JsonValue::Array(tests) = parse_tree(&data).unwrap() else { panic!("not an array") };
            for (i, test) in tests.iter().enumerate() {
                println!("=== {} {}", i, String::from_utf8_lossy(&s(test.get("title"))));
                let lines: Vec<String> = match test.get("rules") {
                    Some(JsonValue::Array(a)) => {
                        a.iter().map(|r| String::from_utf8_lossy(&s(Some(r))).into_owned()).collect()
                    }
                    _ => Vec::new(),
                };
                let mut rules = RulesSet::new();
                rules.properties = RulesSetProperties::with_debug_log(Box::new(CaptureLog::default()));
                let (processor, ctl_args) = configure(&mut rules, &lines);
                let ms = ModSecurity::new();
                {
                    let req = test.get("request").unwrap();
                    let mut t = Transaction::new(&ms, &rules, None);
                    t.process_connection("200.249.12.31", 123, "200.249.12.31", 80);
                    t.process_uri(&s(req.get("uri")), &s(req.get("method")), b"1.1");
                    if let Some(JsonValue::Object(h)) = req.get("headers") {
                        for (k, v) in h {
                            t.add_request_header(k, &s(Some(v)));
                        }
                    }
                    t.process_request_headers();
                    if let Some(p) = processor {
                        t.request_body_processor = p;
                    }
                    if let Some(a) = ctl_args {
                        t.sec_xml_parse_xml_into_args = Some(a);
                    }
                    let mut body = Vec::new();
                    if let Some(JsonValue::Array(b)) = req.get("body") {
                        for l in b {
                            body.extend_from_slice(&s(Some(l)));
                        }
                    }
                    t.append_request_body(&body);
                    t.process_request_body();
                    #[cfg(feature = "libxml2")]
                    xml_rules(&mut t, &lines);
                    let mut vars = Vec::new();
                    t.vars.args.resolve(&mut vars);
                    for v in vars.iter().rev() {
                        println!("ARG {}={}", String::from_utf8_lossy(v.key()), String::from_utf8_lossy(v.value()));
                    }
                    println!("REQBODY_ERROR_MSG {}", String::from_utf8_lossy(&t.vars.reqbody_error_msg.value));
                }
                for m in log(&rules) {
                    if PREFIXES.iter().any(|p| m.starts_with(p)) {
                        println!("{}", m);
                    }
                }
            }
        }
    }
}
