//! A part of the body, and what the parser does with the lines of one:
//! its headers, then its data.

use std::sync::Arc;

use modsecurity_compat::chars::is_space;
use modsecurity_types::ms_dbg;

use super::{Context, MULTIPART_BUF_SIZE, Multipart, MultipartPartTmpFile, find};

/// What a part holds: a form field or a file, as its headers say.
#[derive(Debug)]
pub(super) enum PartKind {
    /// A form field: its value is [`MultipartPart::value`].
    Field,
    File(FilePart),
}

/// The data of a file part.
#[derive(Debug, Default)]
pub(super) struct FilePart {
    /// The temporary file holding the data, when the data is saved.
    pub(super) tmp_file: Option<Arc<MultipartPartTmpFile>>,
    /// The size of the file data read so far.
    pub(super) size: usize,
    /// Where the file data starts in the body (0 until the first data).
    pub(super) offset: usize,
}

/// What the lines of a part are read as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PartState {
    Headers,
    Data,
}

/// Part headers: name -> (offset, value); names compare case insensitively.
type PartHeaders = Vec<(Vec<u8>, (usize, Vec<u8>))>;

/// A part of the body: a form field or a file.
#[derive(Debug)]
pub(super) struct MultipartPart {
    pub(super) kind: PartKind,

    pub(super) name: Vec<u8>,
    pub(super) name_offset: usize,

    /// The value of a form field, or the content of a file that is saved.
    pub(super) value: Vec<u8>,
    /// Where the value starts: for a form field, the offset of its first
    /// buffer (the first one whose offset is not 0, since 0 means not set);
    /// for a file, the offset of the data written last.
    pub(super) value_offset: usize,

    /// The file name as supplied by the browser. The headers are read
    /// before the part is known to be a file: a file name is what makes it
    /// one.
    pub(super) filename: Vec<u8>,
    /// The file name of the `filename*` parameter, percent-decoded. Where
    /// it is set, it takes precedence over [`Self::filename`] (RFC 6266).
    pub(super) filename_star: Vec<u8>,
    pub(super) filename_offset: usize,
    pub(super) filename_star_offset: usize,

    pub(super) filename_charset: Vec<u8>,
    pub(super) filename_charset_offset: usize,

    pub(super) filename_language: Vec<u8>,
    pub(super) filename_language_offset: usize,

    /// The header a folded line continues (empty when there is none).
    last_header_name: Vec<u8>,
    headers: PartHeaders,
    /// The header line being read, with the lines folded into it.
    last_header_line: Vec<u8>,
    /// The complete header lines, with their offsets.
    pub(super) header_lines: Vec<(usize, Vec<u8>)>,

    /// Where the data starts and how long it is, as the debug log shows
    /// them.
    pub(super) offset: usize,
    pub(super) length: usize,
}

impl MultipartPart {
    pub(super) fn new() -> Self {
        MultipartPart {
            kind: PartKind::Field,
            name: Vec::new(),
            name_offset: 0,
            value: Vec::new(),
            value_offset: 0,
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

    /// Moves the header line being read to the complete ones; `offset` is
    /// where it ends.
    fn finish_header_line(&mut self, offset: usize) {
        if !self.last_header_line.is_empty() {
            let line = std::mem::take(&mut self.last_header_line);
            self.header_lines.push((offset.wrapping_sub(line.len()), line));
        }
    }

    /// The file, for a file part.
    pub(super) fn file(&self) -> Option<&FilePart> {
        match &self.kind {
            PartKind::File(file) => Some(file),
            PartKind::Field => None,
        }
    }

    /// Counts `n` more bytes of file data read up to `offset`.
    fn grow_file(&mut self, n: usize, offset: usize) {
        if let PartKind::File(file) = &mut self.kind {
            file.size += n;
            if file.offset == 0 {
                file.offset = offset.wrapping_sub(file.size);
            }
        }
        self.length = self.length.wrapping_add(n);
    }
}

impl Multipart {
    /// Handles a line of the headers of the part `mpp`. A failure only
    /// records the error: it does not stop the processing of the body.
    pub(super) fn process_part_header(
        &mut self,
        cx: &mut dyn Context,
        mpp: &mut MultipartPart,
        line: &[u8],
        offset: usize,
    ) {
        if line.contains(&0) {
            return self.fail(cx, 1, "Multipart: Nul byte in part headers.");
        }

        // Header lines count in the length of the body without files.
        self.reqbody_no_files_length += line.len();

        if line.ends_with(b"\r\n") {
            self.flags.crlf_line = true;
        } else {
            self.flags.lf_line = true;
        }

        if line == b"\r\n" || line == b"\n" {
            self.end_of_part_headers(cx, mpp, offset);
        } else if is_space(line[0]) {
            self.folded_header_line(cx, mpp, line);
        } else {
            self.new_header_line(cx, mpp, line, offset);
        }
    }

    /// The empty line after the headers: reads the Content-Disposition
    /// header, which says what the part is, and turns to its data.
    fn end_of_part_headers(&mut self, cx: &mut dyn Context, mpp: &mut MultipartPart, offset: usize) {
        mpp.finish_header_line(offset);

        let Some((cd_offset, header_value)) = mpp.header(b"Content-Disposition").cloned() else {
            return self.fail(cx, 1, "Multipart: Part missing Content-Disposition header.");
        };

        if let Err(rc) = self.parse_content_disposition(cx, mpp, &header_value, cd_offset) {
            return self.fail(
                cx,
                1,
                format!(
                    "Multipart: Invalid Content-Disposition header ({}): {}",
                    rc,
                    String::from_utf8_lossy(&header_value)
                ),
            );
        }

        if mpp.name.is_empty() {
            return self.fail(cx, 1, "Multipart: Content-Disposition header missing name field.");
        }

        if !mpp.filename.is_empty() || !mpp.filename_star.is_empty() {
            // Some parsers use crude methods to extract the name and
            // filename values from the C-D header. We need to check for
            // the case where they didn't understand C-D but we did: the
            // header must have `filename=` or `filename*=` as written.
            let hv = &header_value;
            if find(hv, b"filename=").is_none() && find(hv, b"filename*=").is_none() {
                return self.fail(cx, 1, "Multipart: Invalid Content-Disposition header (filename).");
            }

            mpp.kind = PartKind::File(FilePart::default());
        } else {
            mpp.kind = PartKind::Field;
        }

        self.part_state = PartState::Data;
        self.part_data_read = false;
        mpp.last_header_name.clear();
    }

    /// A line that starts with whitespace: it continues the previous
    /// header.
    fn folded_header_line(&mut self, cx: &mut dyn Context, mpp: &mut MultipartPart, line: &[u8]) {
        self.flags.header_folding = true;

        // Header folding is SP or HTAB (RFC 5322), but PHP and perhaps
        // others take any whitespace: it is accepted, with a flag set.
        if line[0] != b'\t' && line[0] != b' ' {
            self.flags.invalid_header_folding = true;
        }

        if mpp.last_header_name.is_empty() {
            // we are not building a header at this moment
            return self.fail(cx, 1, "Multipart: Invalid part header (folding error).");
        }

        // locate the beginning of data
        let mut data = 0;
        while line.get(data).is_some_and(|&c| is_space(c)) {
            // Any other whitespace in the folding prefix is invalid header
            // folding too.
            if line[data] != b'\t' && line[data] != b' ' {
                self.flags.invalid_header_folding = true;
            }
            data += 1;
        }

        let mut continuation = line[data..].to_vec();
        chomp(&mut continuation);

        // update the header value in the table
        let name = mpp.last_header_name.clone();
        let value = &mut mpp.header_mut(&name).expect("header being built").1;
        value.push(b' ');
        value.extend_from_slice(&continuation);
        let value = value.clone();

        ms_dbg!(
            cx,
            9,
            "Multipart: Continued folder header \"{}\" with \"{}\"",
            String::from_utf8_lossy(&name),
            String::from_utf8_lossy(&line[data..])
        );

        if value.len() > MULTIPART_BUF_SIZE {
            return self.fail(cx, 1, "Multipart: Part header too long.");
        }

        mpp.last_header_line = [&name[..], b": ", &value].concat();
    }

    /// A header line: `name: value`.
    fn new_header_line(&mut self, cx: &mut dyn Context, mpp: &mut MultipartPart, line: &[u8], offset: usize) {
        mpp.finish_header_line(offset);

        let Some(colon) = line.iter().position(|&c| c == b':') else {
            return self.fail(
                cx,
                1,
                format!("Multipart: Invalid part header (colon missing): {}", String::from_utf8_lossy(line)),
            );
        };

        let name = &line[..colon];
        if name.is_empty() {
            return self.fail(cx, 1, "Multipart: Invalid part header (header name missing).");
        }

        // check if multipart header contains any invalid characters
        if name.iter().any(|&ch| !(33..=126).contains(&ch)) {
            return self.fail(cx, 1, "Multipart: Invalid part header (contains invalid character).");
        }

        // The value, after the colon and blanks.
        let mut data = colon + 1;
        while matches!(line.get(data), Some(b'\t' | b' ')) {
            data += 1;
        }
        let mut value = line[data..].to_vec();
        chomp(&mut value);

        // A repeated header is flagged and ignored.
        if mpp.header(name).is_some() {
            self.flags.duplicate_part_header = true;
            ms_dbg!(cx, 1, "Multipart: Duplicate part header: {}.", String::from_utf8_lossy(name));
            return;
        }

        mpp.last_header_name = name.to_vec();

        ms_dbg!(
            cx,
            9,
            "Multipart: Added part header \"{}\" \"{}\".",
            String::from_utf8_lossy(name),
            String::from_utf8_lossy(&value)
        );
        mpp.headers.push((name.to_vec(), (offset.wrapping_sub(line.len()).wrapping_add(data), value)));

        // The line without its line break.
        let end = line.len() - if line.ends_with(b"\r\n") { 2 } else { 1 };
        mpp.last_header_line = line[..end].to_vec();
    }

    /// Adds the buffer to the data of the part `mpp` (its file or its
    /// value), holding back a trailing line break that may belong to the
    /// next boundary: it is cut from `buf`. `false` when a file could not
    /// be written.
    pub(super) fn process_part_data(
        &mut self,
        cx: &mut dyn Context,
        mpp: &mut MultipartPart,
        buf: &mut Vec<u8>,
        offset: usize,
    ) -> bool {
        self.part_data_read = true;

        let line_break: &'static [u8] = if buf.ends_with(b"\r\n") {
            b"\r\n"
        } else if buf.ends_with(b"\n") {
            b"\n"
        } else {
            b""
        };
        buf.truncate(buf.len() - line_break.len());

        // remember where we started
        if mpp.length == 0 {
            mpp.offset = self.buf_offset;
        }

        match mpp.kind {
            PartKind::File(_) => {
                if !self.add_file_data(cx, mpp, buf, offset) {
                    return false;
                }
            }
            PartKind::Field => {
                // The buffer contains data so increase the data length
                // counter.
                let len = self.reserve.len() + buf.len();
                self.reqbody_no_files_length += len;
                mpp.length = mpp.length.wrapping_add(len);

                ms_dbg!(
                    cx,
                    9,
                    "Multipart: Added data to variable: {}{}",
                    String::from_utf8_lossy(self.reserve),
                    String::from_utf8_lossy(buf)
                );
                if mpp.value_offset == 0 {
                    mpp.value_offset = self.buf_offset;
                }
                mpp.value.extend_from_slice(self.reserve);
                mpp.value.extend_from_slice(buf);
            }
        }

        // Keep the line break for the next data; the one kept before is
        // part of the data now.
        if line_break.is_empty() {
            self.buf_offset = self.buf_offset.wrapping_sub(self.reserve.len());
        } else {
            self.buf_offset = self.buf_offset.wrapping_add(line_break.len());
        }
        self.reserve = line_break;

        true
    }

    /// File data: written to the temporary file of the part if uploads are
    /// kept or saved, and only counted otherwise.
    fn add_file_data(&mut self, cx: &mut dyn Context, mpp: &mut MultipartPart, data: &[u8], offset: usize) -> bool {
        let uploads = cx.uploads();
        let mut extract = uploads.keep_files == Some(true) || uploads.tmp_save_files == Some(true);

        // check if the file limit has been reached
        let limit = uploads.file_limit;
        if extract && limit != 0 && self.nfiles >= limit {
            if !self.flags.file_limit_exceeded {
                self.fail(
                    cx,
                    1,
                    format!(
                        "Multipart: Upload file limit exceeded {}. Use SecUploadFileLimit to change the limit.",
                        limit
                    ),
                );
                self.flags.file_limit_exceeded = true;
            }
            extract = false;
        }

        // Files go to disk only when they are kept (`SecUploadKeepFiles`)
        // or saved to be inspected (`SecTmpSaveUploadedFiles`); otherwise
        // only their size is counted.
        if !extract {
            mpp.grow_file(data.len() + self.reserve.len(), offset);
            return true;
        }

        // first create a temporary file if we don't have it already
        let PartKind::File(file) = &mut mpp.kind else { unreachable!("file data of a form field") };
        if file.tmp_file.is_none() {
            let tmp = Arc::new(MultipartPartTmpFile::open(cx));
            cx.keep_tmp_file(Arc::clone(&tmp));
            file.tmp_file = Some(Arc::clone(&tmp));

            // do we have an opened file?
            if !tmp.is_open() {
                self.fail(cx, 1, format!("Multipart: Failed to create file: {}", tmp.filename()));
                return false;
            }
            // keep track of the files count
            self.nfiles += 1;

            ms_dbg!(
                cx,
                4,
                "Multipart: Created temporary file {} (mode 0{:o}): {}",
                self.nfiles,
                cx.uploads().file_mode,
                tmp.filename()
            );
        }
        let tmp = Arc::clone(file.tmp_file.as_ref().expect("temporary file"));

        // write the reserve first
        if !self.reserve.is_empty() {
            if !tmp.write(self.reserve) {
                self.fail(cx, 1, format!("Multipart: writing to \"{}\" failed", tmp.filename()));
                return false;
            }
            mpp.grow_file(self.reserve.len(), offset);
        }

        // write data to the file
        if !tmp.write(data) {
            self.fail(cx, 1, format!("Multipart: writing to \"{}\" failed", tmp.filename()));
            return false;
        }

        mpp.value.extend_from_slice(data);
        mpp.value_offset = offset.wrapping_sub(data.len());
        mpp.grow_file(data.len(), offset);
        true
    }
}

/// Removes the trailing `\n` and `\r` characters of a header line. A line
/// made of only those is left as it is (sic: C++'s `chomp` erases from
/// `find_last_not_of`, which finds nothing there).
fn chomp(s: &mut Vec<u8>) {
    if let Some(pos) = s.iter().rposition(|&c| c != b'\n' && c != b'\r') {
        s.truncate(pos + 1);
    }
}

#[cfg(test)]
mod tests {
    use super::chomp;

    #[test]
    fn chomp_removes_line_ends() {
        let chomped = |s: &[u8]| {
            let mut v = s.to_vec();
            chomp(&mut v);
            v
        };
        assert_eq!(chomped(b"a: b\r\n"), b"a: b");
        assert_eq!(chomped(b"a\n\r\n\r"), b"a");
        assert_eq!(chomped(b"a\rb\n"), b"a\rb");
        assert_eq!(chomped(b"ab"), b"ab");
        assert_eq!(chomped(b"\r\n"), b"\r\n", "only line ends: unchanged");
        assert_eq!(chomped(b""), b"");
    }
}
