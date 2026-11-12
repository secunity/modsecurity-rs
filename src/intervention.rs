//! Port of `headers/modsecurity/intervention.h`.
//!
//! Inside the library a pending disruptive action is an owned
//! [`Intervention`]. The C API exchanges it as [`ModSecurityIntervention`],
//! whose layout is part of the ABI (`#[repr(C)]`) and whose `url`/`log`
//! strings are `malloc`ed C strings owned by the caller, as in C++; the
//! conversion happens only at that boundary (`msc_intervention`).

use std::ffi::{c_char, c_int};
use std::ptr;

/// A disruptive action requested by the rules (`deny`, `drop`, `redirect`,
/// or a body limit set to `Reject`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Intervention {
    /// The HTTP status code to answer with.
    pub status: i32,
    /// The redirect target (`redirect` action), as raw bytes.
    pub url: Option<Vec<u8>>,
    /// The log message (`[client ...] ModSecurity: Access denied ...`).
    pub log: Option<String>,
    /// Whether the transaction has to be interrupted.
    pub disruptive: bool,
}

impl Default for Intervention {
    fn default() -> Self {
        Intervention { status: 200, url: None, log: None, disruptive: false }
    }
}

impl Intervention {
    /// `intervention::reset`: clears the status and the disruptive flag but
    /// keeps `url` and `log` (as C++ does; a later disruptive action
    /// replaces them).
    pub(crate) fn reset(&mut self) {
        self.status = 200;
        self.disruptive = false;
    }
}

/// `ModSecurityIntervention` of the C API.
#[repr(C)]
#[derive(Debug)]
pub struct ModSecurityIntervention {
    pub status: c_int,
    pub pause: c_int,
    pub url: *mut c_char,
    pub log: *mut c_char,
    pub disruptive: c_int,
}

impl Default for ModSecurityIntervention {
    /// A cleaned intervention (`intervention::clean`).
    fn default() -> Self {
        ModSecurityIntervention { status: 200, pause: 0, url: ptr::null_mut(), log: ptr::null_mut(), disruptive: 0 }
    }
}

impl ModSecurityIntervention {
    /// The part of C++ `Transaction::intervention` that fills the caller's
    /// struct: `url` and `log` are only written when there is one to copy,
    /// and the caller's `disruptive` field is what the C API returns.
    pub(crate) fn fill_from(&mut self, it: &Intervention) {
        if let Some(url) = &it.url {
            self.url = strdup(url);
        }
        self.disruptive = c_int::from(it.disruptive);
        self.status = it.status;
        if let Some(log) = &it.log {
            self.log = strdup(log.as_bytes());
        }
    }

    /// `intervention::free` followed by `intervention::clean`: releases the
    /// strings and resets the struct.
    pub(crate) fn free_and_clean(&mut self) {
        for p in [&mut self.url, &mut self.log] {
            if !p.is_null() {
                // SAFETY: non-null `url`/`log` were allocated with malloc by
                // `strdup` (C API contract: the caller hands back what
                // `msc_intervention` filled).
                unsafe { libc::free(p.cast()) };
            }
        }
        *self = ModSecurityIntervention::default();
    }
}

/// C++ `strdup(s.c_str())`: copies `s` up to its first NUL byte into a
/// `malloc`ed, NUL terminated string that C callers release with `free(3)`.
/// Returns null if the allocation fails.
pub(crate) fn strdup(s: &[u8]) -> *mut c_char {
    let end = s.iter().position(|&c| c == 0).unwrap_or(s.len());
    // SAFETY: `p` has room for `end + 1` bytes; `end` bytes are copied from
    // `s` (which has at least `end` bytes) and the NUL is written after them.
    unsafe {
        let p = libc::malloc(end + 1).cast::<u8>();
        if p.is_null() {
            return ptr::null_mut();
        }
        ptr::copy_nonoverlapping(s.as_ptr(), p, end);
        *p.add(end) = 0;
        p.cast()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    #[test]
    fn fill_and_free_c_struct() {
        let mut c = ModSecurityIntervention::default();
        c.fill_from(&Intervention::default());
        assert!(c.url.is_null() && c.log.is_null());
        assert_eq!((c.status, c.disruptive), (200, 0));

        let it = Intervention {
            status: 302,
            url: Some(b"/\xff\x00tail".to_vec()),
            log: Some("denied".into()),
            disruptive: true,
        };
        c.fill_from(&it);
        assert_eq!((c.status, c.disruptive), (302, 1));
        // Raw bytes are kept, up to the first NUL byte.
        // SAFETY: filled by `fill_from` above.
        assert_eq!(unsafe { CStr::from_ptr(c.url) }.to_bytes(), b"/\xff");
        assert_eq!(unsafe { CStr::from_ptr(c.log) }.to_bytes(), b"denied");
        c.free_and_clean();
        assert!(c.url.is_null() && c.log.is_null());
        assert_eq!((c.status, c.disruptive), (200, 0));
    }

    #[test]
    fn fill_keeps_caller_strings_when_absent() {
        // C++ only overwrites url/log when the transaction has one.
        let mut c = ModSecurityIntervention { url: strdup(b"caller"), ..Default::default() };
        c.fill_from(&Intervention { status: 403, disruptive: true, ..Default::default() });
        // SAFETY: allocated above.
        assert_eq!(unsafe { CStr::from_ptr(c.url) }.to_bytes(), b"caller");
        c.free_and_clean();
    }
}
