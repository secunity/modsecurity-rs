//! Port of `src/utils/system.h` / `src/utils/system.cc`.

use std::ffi::{CStr, CString, c_char, c_int, c_long};

/// `wordexp(3)` bindings (glibc layout; not exposed by the `libc` crate).
#[repr(C)]
struct WordExpT {
    we_wordc: usize,
    we_wordv: *mut *mut c_char,
    we_offs: usize,
}

const WRDE_NOCMD: c_int = 1 << 2;
/// POSIX requires CLOCKS_PER_SEC to be one million on XSI systems.
const CLOCKS_PER_SEC: f64 = 1_000_000.0;

unsafe extern "C" {
    fn wordexp(words: *const c_char, pwordexp: *mut WordExpT, flags: c_int) -> c_int;
    fn wordfree(pwordexp: *mut WordExpT);
    fn clock() -> c_long;
}

/// `cpu_seconds`: process CPU time in seconds.
pub fn cpu_seconds() -> f64 {
    let mut t = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: clock_gettime only writes into `t`.
    if unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut t) } == 0 {
        t.tv_sec as f64 + (t.tv_nsec as f64 / 1_000_000_000.0)
    } else {
        // SAFETY: clock() has no preconditions.
        unsafe { clock() as f64 / CLOCKS_PER_SEC }
    }
}

/// `find_resource`: looks for `resource` as given, through shell expansion,
/// and relative to the directory of `config`. On failure returns an empty
/// string and fills `err` with the places that were tried.
pub fn find_resource(resource: &str, config: &str, err: &mut String) -> String {
    *err = "Looking at: ".to_string();
    if std::fs::File::open(resource).is_ok() {
        return resource.to_string();
    } else {
        err.push_str(&format!("'{}', ", resource));
    }
    if !expand_env(resource, 0).is_empty() {
        return resource.to_string();
    } else {
        err.push_str(&format!("'{}', ", resource));
    }
    let f = format!("{}/{}", get_path(config), resource);
    if std::fs::File::open(&f).is_ok() {
        return f;
    } else {
        err.push_str(&format!("'{}', ", f));
    }
    if !expand_env(&f, 0).is_empty() {
        return f;
    } else {
        err.push_str(&format!("'{}'.", f));
    }
    String::new()
}

/// `get_path`: directory part of `file`. As in C++, a name without any
/// separator is returned unchanged (`npos > 0` and `substr(0, npos)`), and a
/// separator at position 0 yields an empty string.
pub fn get_path(file: &str) -> String {
    match file.rfind(['/', '\\']) {
        Some(0) => String::new(),
        Some(found) => file[..found].to_string(),
        None => file.to_string(),
    }
}

/// `expandEnv`: `wordexp(3)` expansion (no command substitution), keeping
/// only the results that can be opened.
pub fn expand_env(var: &str, flags: i32) -> Vec<String> {
    let mut vars = Vec::new();
    let Ok(c) = CString::new(var) else {
        return vars;
    };
    let mut p = WordExpT { we_wordc: 0, we_wordv: std::ptr::null_mut(), we_offs: 0 };
    let flags = flags | WRDE_NOCMD;
    // SAFETY: `c` is NUL terminated, `p` is valid; wordfree releases it.
    unsafe {
        if wordexp(c.as_ptr(), &mut p, flags) == 0 {
            if p.we_wordc > 0 {
                let mut i = 0;
                loop {
                    let w = *p.we_wordv.add(i);
                    if w.is_null() {
                        break;
                    }
                    let s = CStr::from_ptr(w).to_string_lossy().into_owned();
                    if std::fs::File::open(&s).is_ok() {
                        vars.push(s);
                    }
                    i += 1;
                }
            }
            wordfree(&mut p);
        }
    }
    vars
}

/// `createDir`
pub fn create_dir(dir: &str, mode: u32, error: &mut String) -> bool {
    let Ok(c) = CString::new(dir) else {
        return false;
    };
    // SAFETY: `c` is a valid NUL terminated path.
    let ret = unsafe { libc::mkdir(c.as_ptr(), mode as libc::mode_t) };
    if ret != 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EEXIST) {
            *error = format!("Not able to create directory: {}: {}.", dir, strerror(e.raw_os_error().unwrap_or(0)));
            return false;
        }
    }
    true
}

/// `isFile`
pub fn is_file(f: &str) -> bool {
    match std::fs::metadata(f) {
        Ok(m) => std::fs::File::open(f).is_ok() && m.is_file(),
        Err(_) => false,
    }
}

/// `strerror(errno)`
pub fn strerror(errnum: i32) -> String {
    // SAFETY: strerror returns a pointer to a static (or thread local) NUL
    // terminated string.
    unsafe { CStr::from_ptr(libc::strerror(errnum)).to_string_lossy().into_owned() }
}

/// `strftime` of `t` in the local time zone (`localtime_r`).
pub fn strftime_local(t: i64, fmt: &str) -> String {
    let tt = t as libc::time_t;
    // SAFETY: tm is a plain C struct; localtime_r fills it.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe {
        libc::localtime_r(&tt, &mut tm);
    }
    strftime_tm(&tm, fmt)
}

/// `strftime` of `t` in UTC (`gmtime_r`).
pub fn strftime_utc(t: i64, fmt: &str) -> String {
    let tt = t as libc::time_t;
    // SAFETY: as above.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe {
        libc::gmtime_r(&tt, &mut tm);
    }
    strftime_tm(&tm, fmt)
}

/// `localtime_r`
pub fn localtime(t: i64) -> libc::tm {
    let tt = t as libc::time_t;
    // SAFETY: as above.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe {
        libc::localtime_r(&tt, &mut tm);
    }
    tm
}

fn strftime_tm(tm: &libc::tm, fmt: &str) -> String {
    let Ok(cfmt) = CString::new(fmt) else {
        return String::new();
    };
    let mut buf = vec![0u8; 256];
    // SAFETY: buf is writable for its length, cfmt is NUL terminated and tm
    // is initialised.
    let n = unsafe { libc::strftime(buf.as_mut_ptr() as *mut libc::c_char, buf.len(), cfmt.as_ptr(), tm) };
    buf.truncate(n);
    String::from_utf8_lossy(&buf).into_owned()
}

/// `std::time(nullptr)`
pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}
