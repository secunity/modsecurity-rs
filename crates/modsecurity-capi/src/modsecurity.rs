//! The libmodsecurity C API for the engine instance.

use crate::catch_panic;
use engine::{ModSecurity, ServerLogEntry};
use std::ffi::{CStr, CString, c_char, c_void};

/// `ModSecLogCb` of the C API.
pub type CModSecLogCb = Option<unsafe extern "C" fn(*mut c_void, *const c_void)>;

/// The `void *logCbData` given to `msc_new_transaction*`.
pub struct CLogData(pub *mut c_void);
// SAFETY: the pointer is opaque to the library and only handed back to
// the connector's callback.
unsafe impl Send for CLogData {}

#[unsafe(no_mangle)]
pub extern "C" fn msc_init() -> *mut ModSecurity {
    catch_panic(std::ptr::null_mut(), || Box::into_raw(Box::new(ModSecurity::new())))
}

/// # Safety
/// `msc` must come from `msc_init`. The returned string lives as long as
/// `msc`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_who_am_i(msc: *mut ModSecurity) -> *const c_char {
    catch_panic(std::ptr::null(), || {
        // SAFETY: `msc` is null or comes from `msc_init` (caller contract).
        match unsafe { msc.as_ref() } {
            Some(m) => m.who_am_i_c().as_ptr(),
            None => std::ptr::null(),
        }
    })
}

/// # Safety
/// `msc` must come from `msc_init`; `connector` is a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_set_connector_info(msc: *mut ModSecurity, connector: *const c_char) {
    catch_panic((), || {
        if connector.is_null() {
            return;
        }
        // SAFETY: `msc` is null or comes from `msc_init`, and `connector` is
        // a C string (caller contract).
        let (m, connector) = unsafe { (msc.as_mut(), CStr::from_ptr(connector)) };
        if let Some(m) = m {
            m.set_connector_information(&connector.to_string_lossy());
        }
    })
}

/// # Safety
/// `msc` must come from `msc_init`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_set_log_cb(msc: *mut ModSecurity, cb: CModSecLogCb) {
    catch_panic((), || {
        // SAFETY: `msc` is null or comes from `msc_init` (caller contract).
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
    })
}

/// # Safety
/// `msc` must come from `msc_init` and not be used afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_cleanup(msc: *mut ModSecurity) {
    catch_panic((), || {
        if !msc.is_null() {
            // SAFETY: `msc` is the box `msc_init` leaked, released once
            // (caller contract).
            drop(unsafe { Box::from_raw(msc) });
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn who_am_i_belongs_to_the_instance() {
        let a = msc_init();
        let b = msc_init();
        // SAFETY: `a` and `b` come from `msc_init` and are freed once below.
        unsafe {
            let (sa, sb) = (msc_who_am_i(a), msc_who_am_i(b));
            assert_ne!(sa, sb);
            assert_eq!(msc_who_am_i(a), sa);
            assert!(CStr::from_ptr(sa).to_str().unwrap().starts_with("ModSecurity v3."));
            assert_eq!(CStr::from_ptr(sa), CStr::from_ptr(sb));
            assert!(msc_who_am_i(std::ptr::null_mut()).is_null());
            msc_cleanup(a);
            msc_cleanup(b);
        }
    }
}
