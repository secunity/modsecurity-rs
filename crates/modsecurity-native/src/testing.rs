//! The C library functions the engine's tests compare its Rust code with
//! (the `testing` feature, enabled by the engine's dev-dependency only).

use std::ffi::{CStr, CString, c_char, c_int, c_void};

/// `strftime(fmt, localtime_r(t))` in the C locale.
pub fn strftime_local(t: i64, fmt: &str) -> String {
    let tt = t as libc::time_t;
    let cfmt = CString::new(fmt).expect("a format without NUL");
    let mut buf = [0u8; 256];
    // SAFETY: tm is a plain C struct that localtime_r fills; buf is
    // writable for its length and the format is NUL terminated.
    unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&tt, &mut tm);
        let n = libc::strftime(buf.as_mut_ptr() as *mut c_char, buf.len(), cfmt.as_ptr(), &tm);
        String::from_utf8_lossy(&buf[..n]).into_owned()
    }
}

/// `localtime_r(t).tm_mon` (0 for January).
pub fn localtime_month(t: i64) -> i32 {
    let tt = t as libc::time_t;
    // SAFETY: as in `strftime_local`.
    unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&tt, &mut tm);
        tm.tm_mon
    }
}

/// `strerror(errnum)`.
pub fn strerror(errnum: i32) -> String {
    // SAFETY: strerror returns a NUL terminated string; the comparison
    // only needs it until it is copied.
    unsafe { CStr::from_ptr(libc::strerror(errnum)) }.to_string_lossy().into_owned()
}

// `inet_pton` is part of the C library but not exposed by `libc`.
unsafe extern "C" {
    fn inet_pton(af: c_int, src: *const c_char, dst: *mut c_void) -> c_int;
}

/// `inet_pton(af, src)`: the address bytes (4 for `AF_INET`, 16 for
/// `AF_INET6`), or `None` when it rejects `src`.
pub fn c_inet_pton(af: c_int, src: &[u8]) -> Option<Vec<u8>> {
    let c = CString::new(src).ok()?;
    let mut dst = [0u8; 16];
    // SAFETY: `c` is NUL terminated and `dst` has room for either family.
    let ok = unsafe { inet_pton(af, c.as_ptr(), dst.as_mut_ptr().cast()) > 0 };
    ok.then(|| dst[..if af == libc::AF_INET { 4 } else { 16 }].to_vec())
}

/// `strtol(s, NULL, base)` and whether it set `ERANGE`.
pub fn c_strtol(s: &[u8], base: c_int) -> Option<(i64, bool)> {
    let c = CString::new(s).ok()?;
    // SAFETY: `c` is NUL terminated; a null end pointer is allowed; errno
    // is this thread's.
    unsafe {
        *libc::__errno_location() = 0;
        let v = libc::strtol(c.as_ptr(), std::ptr::null_mut(), base);
        Some((v, *libc::__errno_location() == libc::ERANGE))
    }
}
