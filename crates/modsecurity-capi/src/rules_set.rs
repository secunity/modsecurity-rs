//! The libmodsecurity C API for rule sets (`msc_create_rules_set`, ...).

use crate::catch_panic;
use engine::{LoadError, RulesSet};
use std::ffi::{CStr, CString, c_char, c_int};

fn set_error(error: *mut *const c_char, msg: String) {
    if !error.is_null() {
        let c = CString::new(msg.replace('\0', "")).unwrap_or_default();
        // SAFETY: the caller passes a valid out-pointer; ownership of the
        // string goes to the caller (free with msc_rules_error_cleanup).
        unsafe { *error = c.into_raw() };
    }
}

/// The C API result of a load or merge: the number of rules, or -1 with
/// the parser errors handed to the caller through `error`.
fn c_result(result: Result<usize, LoadError>, error: *mut *const c_char) -> c_int {
    match result {
        Ok(n) => c_int::try_from(n).unwrap_or(c_int::MAX),
        Err(e) => {
            set_error(error, e.message().to_string());
            -1
        }
    }
}

/// The bytes of a C string (none for NULL). Rules are bytes: they need not
/// be UTF-8.
unsafe fn cbytes<'a>(p: *const c_char) -> &'a [u8] {
    if p.is_null() {
        return b"";
    }
    // SAFETY: the C API contract: NUL terminated strings.
    unsafe { CStr::from_ptr(p) }.to_bytes()
}

/// [`catch_panic`] for the functions that load or merge rules: a panic
/// gives -1, with an error message for the caller (who may print it).
fn catch_load_panic(error: *mut *const c_char, f: impl FnOnce() -> c_int) -> c_int {
    catch_panic(None, || Some(f())).unwrap_or_else(|| {
        set_error(error, "ModSecurity: internal error while loading the rules\n".to_string());
        -1
    })
}

/// A file name as the C caller gave it: any bytes but NUL on unix.
#[cfg(unix)]
fn path(name: &[u8]) -> std::borrow::Cow<'_, std::path::Path> {
    use std::os::unix::ffi::OsStrExt;
    std::borrow::Cow::Borrowed(std::path::Path::new(std::ffi::OsStr::from_bytes(name)))
}

/// A file name as the C caller gave it.
#[cfg(not(unix))]
fn path(name: &[u8]) -> std::borrow::Cow<'_, std::path::Path> {
    std::borrow::Cow::Owned(String::from_utf8_lossy(name).into_owned().into())
}

#[unsafe(no_mangle)]
pub extern "C" fn msc_create_rules_set() -> *mut RulesSet {
    catch_panic(std::ptr::null_mut(), || Box::into_raw(Box::new(RulesSet::new())))
}

/// # Safety
/// `rules` must come from `msc_create_rules_set`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_rules_dump(rules: *const RulesSet) {
    catch_panic((), || {
        // SAFETY: `rules` is null or comes from `msc_create_rules_set`
        // (caller contract).
        if let Some(r) = unsafe { rules.as_ref() } {
            r.dump();
        }
    })
}

/// # Safety
/// Both pointers must come from `msc_create_rules_set`.
///
/// Merging a rule set into itself merges nothing and returns 0.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_rules_merge(
    rules_dst: *mut RulesSet,
    rules_from: *mut RulesSet,
    error: *mut *const c_char,
) -> c_int {
    catch_load_panic(error, || {
        if rules_dst == rules_from && !rules_dst.is_null() {
            return 0;
        }
        // SAFETY: both are null or come from `msc_create_rules_set`
        // (caller contract), and they are not the same rule set, so the two
        // mutable references do not alias.
        let (Some(dst), Some(from)) = (unsafe { (rules_dst.as_mut(), rules_from.as_mut()) }) else {
            return -1;
        };
        c_result(dst.merge(from), error)
    })
}

/// # Safety
/// `rules` must come from `msc_create_rules_set`; strings are C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_rules_add_remote(
    rules: *mut RulesSet,
    key: *const c_char,
    uri: *const c_char,
    error: *mut *const c_char,
) -> c_int {
    catch_load_panic(error, || {
        // SAFETY: `rules` is null or comes from `msc_create_rules_set`, the
        // strings are C strings or null (caller contract).
        let (rules, key, uri) = unsafe { (rules.as_mut(), cbytes(key), cbytes(uri)) };
        let Some(r) = rules else {
            return -1;
        };
        // The key and the URL are text; the rules downloaded are bytes.
        c_result(r.load_remote(&String::from_utf8_lossy(key), &String::from_utf8_lossy(uri)), error)
    })
}

/// # Safety
/// `rules` must come from `msc_create_rules_set`; `file` is a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_rules_add_file(
    rules: *mut RulesSet,
    file: *const c_char,
    error: *mut *const c_char,
) -> c_int {
    catch_load_panic(error, || {
        // SAFETY: `rules` is null or comes from `msc_create_rules_set`,
        // `file` is a C string or null (caller contract).
        let (rules, file) = unsafe { (rules.as_mut(), cbytes(file)) };
        let Some(r) = rules else {
            return -1;
        };
        c_result(r.load_file(&path(file)), error)
    })
}

/// # Safety
/// `rules` must come from `msc_create_rules_set`; `plain_rules` is a C
/// string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_rules_add(
    rules: *mut RulesSet,
    plain_rules: *const c_char,
    error: *mut *const c_char,
) -> c_int {
    catch_load_panic(error, || {
        // SAFETY: `rules` is null or comes from `msc_create_rules_set`,
        // `plain_rules` is a C string or null (caller contract).
        let (rules, plain_rules) = unsafe { (rules.as_mut(), cbytes(plain_rules)) };
        let Some(r) = rules else {
            return -1;
        };
        c_result(r.load_bytes(plain_rules, ""), error)
    })
}

/// # Safety
/// `error` must come from one of the `msc_rules_*` functions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_rules_error_cleanup(error: *const c_char) {
    catch_panic((), || {
        if !error.is_null() {
            // SAFETY: `error` is a string `set_error` made with
            // CString::into_raw, released once (caller contract).
            drop(unsafe { CString::from_raw(error as *mut c_char) });
        }
    })
}

/// # Safety
/// `rules` must come from `msc_create_rules_set` and not be used after.
/// Returns 1, or 0 when releasing the rules failed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_rules_cleanup(rules: *mut RulesSet) -> c_int {
    catch_panic(0, || {
        if !rules.is_null() {
            // SAFETY: `rules` is the box `msc_create_rules_set` leaked,
            // released once (caller contract).
            drop(unsafe { Box::from_raw(rules) });
        }
        1
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine::RulesSet;
    use std::ffi::{CStr, CString, c_char};

    /// `msc_rules_add`: the number of rules, or -1 with the error text.
    fn add(rules: *mut RulesSet, text: &str) -> (i32, Option<String>) {
        let text = CString::new(text).unwrap();
        let mut error: *const c_char = std::ptr::null();
        // SAFETY: valid rule set, string and out-pointer.
        let n = unsafe { msc_rules_add(rules, text.as_ptr(), &mut error) };
        let error = (!error.is_null()).then(|| {
            // SAFETY: set by msc_rules_add, released right after.
            let e = unsafe { CStr::from_ptr(error) }.to_string_lossy().into_owned();
            // SAFETY: as above.
            unsafe { msc_rules_error_cleanup(error) };
            e
        });
        (n, error)
    }

    /// A rule set made of Latin-1 bytes (not UTF-8): `@rx \xe9`.
    const LATIN1_RULES: &[u8] = b"SecRuleEngine On\nSecRule ARGS \"@rx \xe9\" \"id:1,phase:1,deny,status:403\"";

    /// Whether `rules` deny a request whose argument is the byte 0xE9.
    fn denies_latin1(rules: *mut RulesSet) -> bool {
        let ms = engine::ModSecurity::new();
        // SAFETY: `rules` is live.
        let mut t = engine::Transaction::new(&ms, unsafe { &*rules }, None);
        t.process_connection("127.0.0.1", 1, "127.0.0.1", 80);
        t.process_uri(b"/?a=%E9", b"GET", b"1.1");
        t.process_request_headers();
        t.intervention().is_some_and(|it| it.status == 403)
    }

    #[test]
    fn rules_that_are_not_utf8_load() {
        let rules = msc_create_rules_set();
        let text = CString::new(LATIN1_RULES).unwrap();
        let mut error: *const c_char = std::ptr::null();
        // SAFETY: valid rule set, string and out-pointer.
        assert_eq!(unsafe { msc_rules_add(rules, text.as_ptr(), &mut error) }, 1);
        assert!(error.is_null());
        assert!(denies_latin1(rules));
        // SAFETY: created above.
        unsafe { msc_rules_cleanup(rules) };
    }

    #[cfg(unix)]
    #[test]
    fn a_file_of_rules_that_are_not_utf8_at_a_path_that_is_not_utf8() {
        use std::os::unix::ffi::OsStrExt;
        let dir = std::env::temp_dir().join(format!("modsec-capi-latin1-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(std::ffi::OsStr::from_bytes(b"r\xe8gles.conf"));
        std::fs::write(&path, LATIN1_RULES).unwrap();

        let rules = msc_create_rules_set();
        let file = CString::new(path.as_os_str().as_bytes()).unwrap();
        let mut error: *const c_char = std::ptr::null();
        // SAFETY: valid rule set, string and out-pointer.
        let n = unsafe { msc_rules_add_file(rules, file.as_ptr(), &mut error) };
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(n, 1);
        assert!(error.is_null());
        assert!(denies_latin1(rules));
        // SAFETY: created above.
        unsafe { msc_rules_cleanup(rules) };
    }

    #[test]
    fn c_api_load_and_merge() {
        let a = msc_create_rules_set();
        assert_eq!(add(a, "SecRule ARGS \"@rx a\" \"id:1,phase:2,pass\"\nSecAction \"id:2,phase:1,pass\""), (2, None));

        let (n, error) = add(a, "SecRuleEngine Bogus");
        assert_eq!(n, -1);
        let first = error.unwrap();
        assert!(first.starts_with("Rules error. File: <<reference missing or not informed>>. Line: 1."), "{first}");
        // The errors accumulate: the next failure reports both.
        let (n, error) = add(a, "SecRuleEngine Bogus");
        assert_eq!(n, -1);
        assert!(error.unwrap().starts_with(&first));

        // Merging a duplicated id fails, but the properties are merged.
        let b = msc_create_rules_set();
        assert_eq!(add(b, "SecRuleEngine On\nSecRule ARGS \"@rx b\" \"id:1,phase:2,pass\""), (1, None));
        let mut error: *const c_char = std::ptr::null();
        // SAFETY: valid rule sets and out-pointer.
        assert_eq!(unsafe { msc_rules_merge(a, b, &mut error) }, -1);
        // SAFETY: set by msc_rules_merge.
        let e = unsafe { CStr::from_ptr(error) }.to_string_lossy().into_owned();
        // SAFETY: as above, released once.
        unsafe { msc_rules_error_cleanup(error) };
        assert!(e.ends_with("Rule id: 1 is duplicated\n"), "{e}");

        // Merging a rule set into itself merges nothing.
        let mut error: *const c_char = std::ptr::null();
        // SAFETY: a valid rule set and out-pointer.
        assert_eq!(unsafe { msc_rules_merge(b, b, &mut error) }, 0);
        assert!(error.is_null());
        // `b`'s SecRuleEngine On reached `a`: its rules intervene (with the
        // engine unset they would only detect).
        assert_eq!(add(a, "SecAction \"id:3,phase:1,deny,status:403\""), (1, None));
        let ms = engine::ModSecurity::new();
        // SAFETY: `a` is live.
        let mut t = engine::Transaction::new(&ms, unsafe { &*a }, None);
        t.process_connection("127.0.0.1", 1, "127.0.0.1", 80);
        t.process_uri(b"/", b"GET", b"1.1");
        t.process_request_headers();
        assert_eq!(t.intervention().map(|it| it.status), Some(403));
        drop(t);

        // SAFETY: created above.
        unsafe {
            msc_rules_cleanup(a);
            msc_rules_cleanup(b);
        }
    }
}
