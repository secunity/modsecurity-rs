//! libc calls with no safe equivalent in std: `setenv`, `mkstemp`,
//! `wordexp` and `gai_strerror`.

use std::ffi::{CStr, CString, c_char, c_int};

/// `setenv(name, value, 1)`. `name` must not be empty or contain `=`, and
/// neither may contain a NUL (callers check: `setenv` rejects those).
pub fn set_env(name: &[u8], value: &[u8]) {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    debug_assert!(!name.is_empty() && !name.contains(&b'=') && !name.contains(&0) && !value.contains(&0));
    // SAFETY: like the C++ code, this mutates the process environment, with
    // the usual caveat about concurrent getenv(3) calls from other threads.
    unsafe { std::env::set_var(OsStr::from_bytes(name), OsStr::from_bytes(value)) };
}

/// `mkstemp(3)`: creates and opens a new file named `template` with its
/// final `XXXXXX` replaced. Returns the name and the file (`None` when it
/// could not be created, or when `template` contains a NUL).
pub fn mkstemp(template: &str) -> (String, Option<std::fs::File>) {
    use std::os::fd::FromRawFd;
    let mut buf = template.as_bytes().to_vec();
    if buf.contains(&0) {
        return (template.to_string(), None);
    }
    buf.push(0);
    // SAFETY: `buf` is a writable, NUL terminated buffer; mkstemp only
    // rewrites its last six characters before the NUL ("XXXXXX").
    let fd = unsafe { libc::mkstemp(buf.as_mut_ptr().cast::<c_char>()) };
    buf.pop();
    let name = String::from_utf8_lossy(&buf).into_owned();
    // SAFETY: mkstemp returned a freshly opened descriptor nothing else owns.
    let file = (fd >= 0).then(|| unsafe { std::fs::File::from_raw_fd(fd) });
    (name, file)
}

/// `wordexp(3)` bindings (glibc layout; not exposed by the `libc` crate).
#[repr(C)]
struct WordExpT {
    we_wordc: usize,
    we_wordv: *mut *mut c_char,
    we_offs: usize,
}

/// `WRDE_NOCMD`: no command substitution.
pub const WRDE_NOCMD: c_int = 1 << 2;

unsafe extern "C" {
    fn wordexp(words: *const c_char, pwordexp: *mut WordExpT, flags: c_int) -> c_int;
    fn wordfree(pwordexp: *mut WordExpT);
}

/// The words of the shell expansion of `words` (`wordexp(3)` with
/// `flags`): empty when the expansion fails or `words` contains a NUL.
pub fn word_expansion(words: &str, flags: c_int) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(c) = CString::new(words) else {
        return out;
    };
    let mut p = WordExpT { we_wordc: 0, we_wordv: std::ptr::null_mut(), we_offs: 0 };
    // SAFETY: `c` is NUL terminated and `p` is valid; on success wordexp
    // fills `we_wordv` with `we_wordc` NUL terminated strings (followed by
    // a null pointer), which are copied before wordfree releases them.
    unsafe {
        if wordexp(c.as_ptr(), &mut p, flags) == 0 {
            for i in 0..p.we_wordc {
                let w = *p.we_wordv.add(i);
                if w.is_null() {
                    break;
                }
                out.push(CStr::from_ptr(w).to_string_lossy().into_owned());
            }
            wordfree(&mut p);
        }
    }
    out
}

/// `gai_strerror(code)`: the text of a `getaddrinfo` error code.
pub fn gai_strerror(code: c_int) -> String {
    // SAFETY: gai_strerror returns a static NUL terminated string.
    unsafe { CStr::from_ptr(libc::gai_strerror(code)) }.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expansion_and_temp_files() {
        let dir = std::env::temp_dir().join(format!("msrs-native-posix-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (name, file) = mkstemp(dir.join("f-XXXXXX").to_str().unwrap());
        assert!(file.is_some());
        assert!(!name.ends_with("XXXXXX"));
        let words = word_expansion(&format!("{}/f-*", dir.to_str().unwrap()), WRDE_NOCMD);
        assert_eq!(words, vec![name.clone()]);
        assert!(word_expansion("$(echo no)", WRDE_NOCMD).is_empty());
        assert!(word_expansion("a\0b", 0).is_empty());
        std::fs::remove_dir_all(&dir).unwrap();

        assert_eq!(mkstemp("a\0b").1.map(|_| ()), None);
        assert!(!gai_strerror(libc::EAI_NONAME).is_empty());
    }
}
