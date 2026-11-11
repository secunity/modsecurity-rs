//! Port of `headers/modsecurity/intervention.h`.
//!
//! `ModSecurityIntervention` is part of the C API, so its layout is kept
//! (`#[repr(C)]`); the `url`/`log` strings are `malloc`ed C strings owned by
//! whoever holds the struct, as in C++.

use std::ffi::{CStr, CString, c_char, c_int};
use std::ptr;

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
        let mut i = ModSecurityIntervention {
            status: 200,
            pause: 0,
            url: ptr::null_mut(),
            log: ptr::null_mut(),
            disruptive: 0,
        };
        clean(&mut i);
        i
    }
}

// SAFETY: the raw pointers are uniquely owned C strings (see module docs);
// moving the struct between threads moves that ownership.
unsafe impl Send for ModSecurityIntervention {}

/// `intervention::reset`
pub fn reset(i: &mut ModSecurityIntervention) {
    i.status = 200;
    i.pause = 0;
    i.disruptive = 0;
}

/// `intervention::clean` (does not free; see [`free`]).
pub fn clean(i: &mut ModSecurityIntervention) {
    i.url = ptr::null_mut();
    i.log = ptr::null_mut();
    reset(i);
}

/// Allocates a C string with `malloc` (C++ `strdup`), so that C callers can
/// release it with `free(3)`.
pub fn strdup(s: &str) -> *mut c_char {
    let c = CString::new(s.replace('\0', "")).unwrap_or_default();
    // SAFETY: `c` is a valid NUL terminated string.
    unsafe { libc::strdup(c.as_ptr()) }
}

/// `strdup` of a byte string: copies up to the first NUL byte (as C++
/// `strdup(str.c_str())` does) into a `malloc`ed C string.
pub fn strdup_bytes(s: &[u8]) -> *mut c_char {
    let end = s.iter().position(|&c| c == 0).unwrap_or(s.len());
    // SAFETY: allocates end + 1 bytes with malloc and fills them; the
    // result is NUL terminated and owned by the caller (release with free).
    unsafe {
        let p = libc::malloc(end + 1) as *mut u8;
        if p.is_null() {
            return ptr::null_mut();
        }
        ptr::copy_nonoverlapping(s.as_ptr(), p, end);
        *p.add(end) = 0;
        p as *mut c_char
    }
}

/// `intervention::freeUrl`
pub fn free_url(i: &mut ModSecurityIntervention) {
    if !i.url.is_null() {
        // SAFETY: url was allocated with malloc (strdup).
        unsafe { libc::free(i.url as *mut libc::c_void) };
        i.url = ptr::null_mut();
    }
}

/// `intervention::freeLog`
pub fn free_log(i: &mut ModSecurityIntervention) {
    if !i.log.is_null() {
        // SAFETY: log was allocated with malloc (strdup).
        unsafe { libc::free(i.log as *mut libc::c_void) };
        i.log = ptr::null_mut();
    }
}

/// `intervention::free`
pub fn free(i: &mut ModSecurityIntervention) {
    free_url(i);
    free_log(i);
}

impl ModSecurityIntervention {
    /// The `url` field as a Rust string (if set).
    pub fn url_str(&self) -> Option<String> {
        if self.url.is_null() {
            None
        } else {
            // SAFETY: non-null url is a NUL terminated C string.
            Some(unsafe { CStr::from_ptr(self.url) }.to_string_lossy().into_owned())
        }
    }

    /// The `log` field as a Rust string (if set).
    pub fn log_str(&self) -> Option<String> {
        if self.log.is_null() {
            None
        } else {
            // SAFETY: non-null log is a NUL terminated C string.
            Some(unsafe { CStr::from_ptr(self.log) }.to_string_lossy().into_owned())
        }
    }
}
