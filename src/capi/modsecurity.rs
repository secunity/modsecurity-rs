//! The libmodsecurity C API for the engine instance.

use crate::modsecurity::{ModSecurity, ServerLogEntry};
use std::ffi::{CStr, CString, c_char, c_void};
use std::sync::Mutex;

/// `ModSecLogCb` of the C API.
pub type CModSecLogCb = Option<unsafe extern "C" fn(*mut c_void, *const c_void)>;

/// The `void *logCbData` given to `msc_new_transaction*`.
pub struct CLogData(pub *mut c_void);
// SAFETY: the pointer is opaque to the library and only handed back to
// the connector's callback, as in C++.
unsafe impl Send for CLogData {}

#[unsafe(no_mangle)]
pub extern "C" fn msc_init() -> *mut ModSecurity {
    Box::into_raw(Box::new(ModSecurity::new()))
}

/// # Safety
/// `msc` must come from `msc_init`. The returned string lives as long as
/// `msc`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_who_am_i(msc: *mut ModSecurity) -> *const c_char {
    static CACHE: Mutex<Option<CString>> = Mutex::new(None);
    let Some(m) = (unsafe { msc.as_ref() }) else {
        return std::ptr::null();
    };
    let mut c = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    let s = c.get_or_insert_with(|| CString::new(m.who_am_i()).unwrap_or_default());
    s.as_ptr()
}

/// # Safety
/// `msc` must come from `msc_init`; `connector` is a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_set_connector_info(msc: *mut ModSecurity, connector: *const c_char) {
    if let (Some(m), false) = (unsafe { msc.as_mut() }, connector.is_null()) {
        let s = unsafe { CStr::from_ptr(connector) }.to_string_lossy().into_owned();
        m.set_connector_information(&s);
    }
}

/// # Safety
/// `msc` must come from `msc_init`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_set_log_cb(msc: *mut ModSecurity, cb: CModSecLogCb) {
    let Some(m) = (unsafe { msc.as_mut() }) else {
        return;
    };
    let Some(cb) = cb else {
        return;
    };
    m.set_server_log_cb(Box::new(move |data, entry| {
        let d = data.and_then(|d| d.downcast_ref::<CLogData>()).map(|d| d.0).unwrap_or(std::ptr::null_mut());
        if let ServerLogEntry::Text(s) = entry {
            let c = CString::new(s.replace('\0', "")).unwrap_or_default();
            // SAFETY: calling the connector's callback with its own data
            // pointer and a NUL terminated string, as libmodsecurity does.
            unsafe { cb(d, c.as_ptr() as *const c_void) };
        }
    }));
}

/// # Safety
/// `msc` must come from `msc_init` and not be used afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_cleanup(msc: *mut ModSecurity) {
    if !msc.is_null() {
        drop(unsafe { Box::from_raw(msc) });
    }
}
