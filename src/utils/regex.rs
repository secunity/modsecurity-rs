//! Port of `src/utils/regex.h` / `src/utils/regex.cc` (PCRE2 build).
//!
//! The PCRE2 C library is used directly through `pcre2-sys` so that the
//! compile options, JIT usage, match limits and error codes are exactly the
//! ones of the C++ implementation. All `unsafe` code of the regex layer is
//! confined to this module.

use pcre2_sys::*;
use std::ptr;

/// `OVECCOUNT` (only meaningful for the legacy PCRE build, kept for parity).
pub const OVECCOUNT: usize = 900;

/// Outcome of a search that may hit PCRE2 limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegexResult {
    Ok,
    ErrorMatchLimit,
    ErrorOther,
}

/// A (sub)match: the matched bytes and their offset.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SMatch {
    m_match: Vec<u8>,
    m_offset: usize,
}

impl SMatch {
    pub fn new(m: &[u8], offset: usize) -> Self {
        SMatch { m_match: m.to_vec(), m_offset: offset }
    }
    pub fn str(&self) -> &[u8] {
        &self.m_match
    }
    pub fn offset(&self) -> usize {
        self.m_offset
    }
}

/// A capture group of a match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SMatchCapture {
    /// E.g. 0 = full match; 6 = capture group 6.
    pub group: usize,
    /// Offset of the match within the analyzed string.
    pub offset: usize,
    pub length: usize,
}

impl SMatchCapture {
    pub fn new(group: usize, offset: usize, length: usize) -> Self {
        SMatchCapture { group, offset, length }
    }
}

/// Helper telling whether the PCRE2 build treats CRLF as a newline sequence.
pub fn crlf_is_newline() -> bool {
    let mut newline: u32 = 0;
    // SAFETY: PCRE2_CONFIG_NEWLINE writes a single uint32_t into `where`.
    unsafe {
        pcre2_config_8(PCRE2_CONFIG_NEWLINE, &mut newline as *mut u32 as *mut _);
    }
    newline == PCRE2_NEWLINE_ANY || newline == PCRE2_NEWLINE_CRLF || newline == PCRE2_NEWLINE_ANYCRLF
}

/// An empty slice may carry a dangling (non-null, unreadable) pointer, but
/// PCRE2 may read the subject pointer even for a zero length subject; use a
/// pointer into a static instead.
fn subject(s: &[u8]) -> &[u8] {
    if s.is_empty() { &b"\0"[..0] } else { s }
}

/// RAII owner of a `pcre2_match_data`.
struct MatchData(*mut pcre2_match_data_8);

impl MatchData {
    fn new(code: *const pcre2_code_8) -> Self {
        // SAFETY: `code` is a valid compiled pattern (callers check
        // `has_error()` first); a null general context selects malloc.
        MatchData(unsafe { pcre2_match_data_create_from_pattern_8(code, ptr::null_mut()) })
    }
    fn ovector(&self) -> *const usize {
        // SAFETY: self.0 is a live match data block.
        unsafe { pcre2_get_ovector_pointer_8(self.0) }
    }
}

impl Drop for MatchData {
    fn drop(&mut self) {
        // SAFETY: allocated by pcre2_match_data_create_from_pattern_8 and
        // freed exactly once.
        unsafe { pcre2_match_data_free_8(self.0) }
    }
}

/// RAII owner of a `pcre2_match_context` (`Pcre2MatchContextPtr`).
struct MatchContext(*mut pcre2_match_context_8);

impl MatchContext {
    fn new(match_limit: u64) -> Self {
        // SAFETY: a null general context selects the default allocator.
        let ctx = unsafe { pcre2_match_context_create_8(ptr::null_mut()) };
        if match_limit > 0 && !ctx.is_null() {
            // SAFETY: ctx is a valid match context.
            unsafe { pcre2_set_match_limit_8(ctx, match_limit as u32) };
        }
        MatchContext(ctx)
    }
}

impl Drop for MatchContext {
    fn drop(&mut self) {
        // SAFETY: allocated above and freed once.
        unsafe { pcre2_match_context_free_8(self.0) }
    }
}

/// A compiled PCRE2 pattern.
pub struct Regex {
    pub pattern: String,
    pc: *mut pcre2_code_8,
    pcje: i32,
}

// SAFETY: a compiled pcre2_code (including its JIT code) is immutable after
// compilation and PCRE2 documents it as safe to share between threads; all
// per-match state (match data, contexts) is allocated per call.
unsafe impl Send for Regex {}
unsafe impl Sync for Regex {}

impl std::fmt::Debug for Regex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Regex").field("pattern", &self.pattern).finish()
    }
}

impl Drop for Regex {
    fn drop(&mut self) {
        if !self.pc.is_null() {
            // SAFETY: compiled by pcre2_compile_8 and freed once.
            unsafe { pcre2_code_free_8(self.pc) }
        }
    }
}

impl Regex {
    /// `Regex(pattern, ignoreCase = false, multiLine = true)`
    pub fn new(pattern: &str) -> Self {
        Self::with_options(pattern.as_bytes(), false, true)
    }

    /// `Regex(pattern, ignoreCase)`
    pub fn new_case(pattern: &str, ignore_case: bool) -> Self {
        Self::with_options(pattern.as_bytes(), ignore_case, true)
    }

    /// `Regex(pattern, ignoreCase, multiLine)`; the pattern is a byte string.
    pub fn with_options(pattern: &[u8], ignore_case: bool, multi_line: bool) -> Self {
        let pattern: Vec<u8> = if pattern.is_empty() { b".*".to_vec() } else { pattern.to_vec() };
        let mut options = PCRE2_DOTALL | if multi_line { PCRE2_MULTILINE } else { PCRE2_DOLLAR_ENDONLY };
        if ignore_case {
            options |= PCRE2_CASELESS;
        }
        let mut errornumber: i32 = 0;
        let mut erroroffset: usize = 0;
        // The C++ code passes the pattern as a NUL terminated C string, so a
        // pattern stops at its first NUL byte.
        let len = pattern.iter().position(|&c| c == 0).unwrap_or(pattern.len());
        // SAFETY: pattern points to `len` readable bytes; out-params are
        // valid; a null compile context selects defaults.
        let pc = unsafe {
            pcre2_compile_8(pattern.as_ptr(), len, options, &mut errornumber, &mut erroroffset, ptr::null_mut())
        };
        let pcje = if pc.is_null() {
            -1
        } else {
            // SAFETY: pc is a valid compiled pattern.
            unsafe { pcre2_jit_compile_8(pc, PCRE2_JIT_COMPLETE) }
        };
        Regex { pattern: String::from_utf8_lossy(&pattern).into_owned(), pc, pcje }
    }

    pub fn has_error(&self) -> bool {
        self.pc.is_null()
    }

    /// Runs one match attempt, JIT first and interpreter on JIT stack
    /// exhaustion (or when JIT is unavailable), as the C++ code does.
    fn exec(
        &self,
        s: &[u8],
        offset: usize,
        options: u32,
        md: &MatchData,
        ctx: *mut pcre2_match_context_8,
        use_jit: bool,
    ) -> i32 {
        let s = subject(s);
        let mut rc = 0;
        if use_jit && self.pcje == 0 {
            // SAFETY: pc is valid (callers check has_error), `s` is readable
            // for its length, md belongs to this pattern.
            rc = unsafe { pcre2_jit_match_8(self.pc, s.as_ptr(), s.len(), offset, options, md.0, ctx) };
        }
        if !use_jit || self.pcje != 0 || rc == PCRE2_ERROR_JIT_STACKLIMIT {
            // SAFETY: as above.
            rc = unsafe { pcre2_match_8(self.pc, s.as_ptr(), s.len(), offset, options | PCRE2_NO_JIT, md.0, ctx) };
        }
        rc
    }

    fn ovec(md: &MatchData, i: usize) -> (usize, usize) {
        // SAFETY: the ovector holds at least `rc` pairs for a successful
        // match and callers only read pairs below `rc`.
        unsafe {
            let ov = md.ovector();
            (*ov.add(2 * i), *ov.add(2 * i + 1))
        }
    }

    /// `searchAll`
    pub fn search_all(&self, s: &[u8]) -> Vec<SMatch> {
        // std::list with push_front: build reversed.
        let mut ret: Vec<SMatch> = Vec::new();
        if self.has_error() {
            return ret;
        }
        let md = MatchData::new(self.pc);
        let mut offset = 0usize;
        loop {
            let mut rc = self.exec(s, offset, 0, &md, ptr::null_mut(), true);
            let mut i = 0;
            while i < rc {
                let (start, end) = Self::ovec(&md, i as usize);
                if end > s.len() || start > end {
                    rc = -1;
                    break;
                }
                let len = end - start;
                offset = start + len;
                ret.insert(0, SMatch::new(&s[start..end], start));
                if len == 0 {
                    rc = 0;
                    break;
                }
                i += 1;
            }
            if rc <= 0 {
                break;
            }
        }
        ret
    }

    /// `searchOneMatch`
    pub fn search_one_match(&self, s: &[u8], captures: &mut Vec<SMatchCapture>, match_limit: u64) -> RegexResult {
        if self.has_error() {
            return RegexResult::ErrorOther;
        }
        let ctx = MatchContext::new(match_limit);
        let md = MatchData::new(self.pc);
        let rc = self.exec(s, 0, 0, &md, ctx.0, true);
        for i in 0..rc.max(0) {
            let (start, end) = Self::ovec(&md, i as usize);
            if end > s.len() || start > end {
                continue;
            }
            captures.push(SMatchCapture::new(i as usize, start, end - start));
        }
        Self::to_regex_result(rc)
    }

    /// `searchGlobal`
    pub fn search_global(&self, s: &[u8], captures: &mut Vec<SMatchCapture>, match_limit: u64) -> RegexResult {
        if self.has_error() {
            return RegexResult::ErrorOther;
        }
        let mut prev_match_zero_length = false;
        let ctx = MatchContext::new(match_limit);
        let md = MatchData::new(self.pc);
        let mut start_offset = 0usize;
        while start_offset <= s.len() {
            let options = if prev_match_zero_length { PCRE2_NOTEMPTY_ATSTART | PCRE2_ANCHORED } else { 0 };
            // The C++ code uses pcre2_match (JIT is still used implicitly
            // unless the options require the interpreter).
            let subj = subject(s);
            // SAFETY: as in `exec` (`subj` is never a dangling pointer).
            let rc = unsafe { pcre2_match_8(self.pc, subj.as_ptr(), s.len(), start_offset, options, md.0, ctx.0) };
            let r = Self::to_regex_result(rc);
            if r != RegexResult::Ok {
                return r;
            }
            if rc > 0 {
                let first_group = captures.len();
                for i in 0..rc {
                    let (start, end) = Self::ovec(&md, i as usize);
                    if end > s.len() || start > end {
                        continue;
                    }
                    let len = end - start;
                    captures.push(SMatchCapture::new(first_group + i as usize, start, len));
                    if i == 0 {
                        if len > 0 {
                            start_offset = end;
                            prev_match_zero_length = false;
                        } else if start_offset == s.len() {
                            start_offset += 1;
                        } else {
                            prev_match_zero_length = true;
                        }
                    }
                }
            } else if prev_match_zero_length {
                start_offset += 1;
                if crlf_is_newline()
                    && start_offset < s.len()
                    && s[start_offset - 1] == b'\r'
                    && s[start_offset] == b'\n'
                {
                    start_offset += 1;
                }
                prev_match_zero_length = false;
            } else {
                break;
            }
        }
        RegexResult::Ok
    }

    /// `search(s, match)`: stores the last captured group of the first match.
    pub fn search_match(&self, s: &[u8], m: &mut SMatch) -> i32 {
        if self.has_error() {
            return 0;
        }
        let md = MatchData::new(self.pc);
        // The C++ code turns the return value into a boolean before reading
        // the ovector, so the "last group" is always group 0.
        let rc = self.exec(s, 0, 0, &md, ptr::null_mut(), false);
        let ret = (rc > 0) as i32;
        if ret > 0 {
            // SAFETY: a successful match has at least one ovector pair.
            let (a, b) = unsafe {
                let ov = md.ovector();
                (*ov.add(ret as usize - 1), *ov.add(ret as usize))
            };
            if a <= b && b <= s.len() {
                *m = SMatch::new(&s[a..b], 0);
            }
        }
        ret
    }

    /// `search(s)`: 1 on match, 0 otherwise.
    pub fn search(&self, s: &[u8]) -> i32 {
        if self.has_error() {
            return 0;
        }
        let md = MatchData::new(self.pc);
        let rc = self.exec(s, 0, 0, &md, ptr::null_mut(), true);
        (rc > 0) as i32
    }

    fn to_regex_result(rc: i32) -> RegexResult {
        if rc > 0 || rc == PCRE2_ERROR_NOMATCH {
            RegexResult::Ok
        } else if rc == PCRE2_ERROR_MATCHLIMIT {
            RegexResult::ErrorMatchLimit
        } else {
            RegexResult::ErrorOther
        }
    }
}

/// `regex_search(s, match, regex)`
pub fn regex_search_match(s: &[u8], m: &mut SMatch, regex: &Regex) -> i32 {
    regex.search_match(s, m)
}

/// `regex_search(s, regex)`
pub fn regex_search(s: &[u8], regex: &Regex) -> i32 {
    regex.search(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_search() {
        let r = Regex::new("b+");
        assert_eq!(r.search(b"abbbc"), 1);
        assert_eq!(r.search(b"ac"), 0);
        let all = r.search_all(b"abxbb");
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].str(), b"bb");
        assert_eq!(all[1].str(), b"b");
    }

    #[test]
    fn captures_and_global() {
        let r = Regex::new("(a)(b)?");
        let mut c = Vec::new();
        assert_eq!(r.search_one_match(b"xab", &mut c, 0), RegexResult::Ok);
        assert_eq!(c.len(), 3);
        let mut g = Vec::new();
        assert_eq!(r.search_global(b"aab", &mut g, 0), RegexResult::Ok);
        assert_eq!(g[0].offset, 0);
    }

    #[test]
    fn empty_subject() {
        assert_eq!(Regex::new("^$").search(b""), 1);
        assert_eq!(Regex::new("a").search(&Vec::new()), 0);
        let mut c = Vec::new();
        assert_eq!(Regex::new("x*").search_global(b"", &mut c, 0), RegexResult::Ok);
    }

    #[test]
    fn invalid_pattern() {
        let r = Regex::new("(");
        assert!(r.has_error());
        assert_eq!(r.search(b"("), 0);
    }
}
