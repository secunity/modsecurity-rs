//! The libmodsecurity C API for rule sets (`msc_create_rules_set`, ...).

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

unsafe fn cstr<'a>(p: *const c_char) -> &'a str {
    if p.is_null() {
        return "";
    }
    // SAFETY: the C API contract: NUL terminated strings.
    unsafe { CStr::from_ptr(p) }.to_str().unwrap_or("")
}

#[unsafe(no_mangle)]
pub extern "C" fn msc_create_rules_set() -> *mut RulesSet {
    Box::into_raw(Box::new(RulesSet::new()))
}

/// # Safety
/// `rules` must come from `msc_create_rules_set`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_rules_dump(rules: *const RulesSet) {
    if let Some(r) = unsafe { rules.as_ref() } {
        r.dump();
    }
}

/// # Safety
/// Both pointers must come from `msc_create_rules_set`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_rules_merge(
    rules_dst: *mut RulesSet,
    rules_from: *mut RulesSet,
    error: *mut *const c_char,
) -> c_int {
    let (Some(dst), Some(from)) = (unsafe { rules_dst.as_mut() }, unsafe { rules_from.as_mut() }) else {
        return -1;
    };
    c_result(dst.merge(from), error)
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
    let Some(r) = (unsafe { rules.as_mut() }) else {
        return -1;
    };
    c_result(r.load_remote(unsafe { cstr(key) }, unsafe { cstr(uri) }), error)
}

/// # Safety
/// `rules` must come from `msc_create_rules_set`; `file` is a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_rules_add_file(
    rules: *mut RulesSet,
    file: *const c_char,
    error: *mut *const c_char,
) -> c_int {
    let Some(r) = (unsafe { rules.as_mut() }) else {
        return -1;
    };
    c_result(r.load_from_uri(unsafe { cstr(file) }), error)
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
    let Some(r) = (unsafe { rules.as_mut() }) else {
        return -1;
    };
    c_result(r.load(unsafe { cstr(plain_rules) }), error)
}

/// # Safety
/// `error` must come from one of the `msc_rules_*` functions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_rules_error_cleanup(error: *const c_char) {
    if !error.is_null() {
        drop(unsafe { CString::from_raw(error as *mut c_char) });
    }
}

/// # Safety
/// `rules` must come from `msc_create_rules_set` and not be used after.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_rules_cleanup(rules: *mut RulesSet) -> c_int {
    if !rules.is_null() {
        drop(unsafe { Box::from_raw(rules) });
    }
    1
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
            unsafe { msc_rules_error_cleanup(error) };
            e
        });
        (n, error)
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
        unsafe { msc_rules_error_cleanup(error) };
        assert!(e.ends_with("Rule id: 1 is duplicated\n"), "{e}");
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
