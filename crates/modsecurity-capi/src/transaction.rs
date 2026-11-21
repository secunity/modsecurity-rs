//! The libmodsecurity C API for transactions (`msc_new_transaction`, ...).

use crate::catch_panic;
use crate::intervention::{self, ModSecurityIntervention};
use crate::modsecurity::CLogData;
use engine::ModSecurity;
use engine::RulesSet;
use engine::Transaction;
use std::ffi::{CStr, c_char, c_int, c_uchar, c_void};
use std::ptr;

/// The C API hands out transactions without a lifetime; the connector
/// guarantees the `ModSecurity` and `RulesSet` outlive them.
pub type CTransaction = Transaction<'static>;

/// The bytes of a C string (none for NULL).
///
/// # Safety
/// `p` must be null or a NUL terminated string that outlives `'a`.
unsafe fn bytes<'a>(p: *const c_char) -> &'a [u8] {
    if p.is_null() {
        return b"";
    }
    // SAFETY: C API contract: NUL terminated strings.
    unsafe { CStr::from_ptr(p) }.to_bytes()
}

/// The `len` bytes at `p` (none for NULL).
///
/// # Safety
/// `p` must be null or point to `len` readable bytes that outlive `'a`.
unsafe fn slice<'a>(p: *const c_uchar, len: usize) -> &'a [u8] {
    if p.is_null() || len == 0 {
        return b"";
    }
    // SAFETY: C API contract: `p` points to `len` readable bytes.
    unsafe { std::slice::from_raw_parts(p, len) }
}

/// The engine and the rules of a new transaction; `None` when one of them
/// is NULL.
///
/// # Safety
/// `ms` and `rules` must be null or valid, and outlive the transaction.
unsafe fn instance(ms: *mut ModSecurity, rules: *mut RulesSet) -> Option<(&'static ModSecurity, &'static RulesSet)> {
    // SAFETY: per the contract; the C API caller keeps both alive for as
    // long as the transaction (see `CTransaction`).
    unsafe { Some((ms.as_ref()?, rules.as_ref()?)) }
}

/// # Safety
/// `ms` and `rules` must be valid and outlive the transaction. NULL when
/// one of them is NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_new_transaction(
    ms: *mut ModSecurity,
    rules: *mut RulesSet,
    log_cb_data: *mut c_void,
) -> *mut CTransaction {
    catch_panic(ptr::null_mut(), || {
        // SAFETY: see the function contract.
        let Some((ms, rules)) = (unsafe { instance(ms, rules) }) else {
            return ptr::null_mut();
        };
        Box::into_raw(Box::new(Transaction::new(ms, rules, Some(Box::new(CLogData(log_cb_data))))))
    })
}

/// # Safety
/// As [`msc_new_transaction`]; `id` is a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_new_transaction_with_id(
    ms: *mut ModSecurity,
    rules: *mut RulesSet,
    id: *const c_char,
    log_cb_data: *mut c_void,
) -> *mut CTransaction {
    catch_panic(ptr::null_mut(), || {
        // SAFETY: see the function contract.
        let (Some((ms, rules)), id) = (unsafe { (instance(ms, rules), bytes(id)) }) else {
            return ptr::null_mut();
        };
        let id = String::from_utf8_lossy(id);
        Box::into_raw(Box::new(Transaction::with_id(ms, rules, &id, Some(Box::new(CLogData(log_cb_data))))))
    })
}

macro_rules! tx {
    ($t:expr) => {
        // SAFETY: the C API contract: null or a live transaction pointer.
        match unsafe { $t.as_mut() } {
            Some(t) => t,
            None => return 0,
        }
    };
}

/// # Safety
/// `t` must come from `msc_new_transaction*`; strings are C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_process_connection(
    t: *mut CTransaction,
    client: *const c_char,
    c_port: c_int,
    server: *const c_char,
    s_port: c_int,
) -> c_int {
    catch_panic(0, || {
        let t = tx!(t);
        // SAFETY: C strings or null (caller contract).
        let (client, server) = unsafe { (bytes(client), bytes(server)) };
        // A number that is not a port is reported as port 0.
        let port = |p: c_int| u16::try_from(p).unwrap_or(0);
        t.process_connection(
            &String::from_utf8_lossy(client),
            port(c_port),
            &String::from_utf8_lossy(server),
            port(s_port),
        );
        1
    })
}

/// # Safety
/// As above.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_process_uri(
    t: *mut CTransaction,
    uri: *const c_char,
    protocol: *const c_char,
    http_version: *const c_char,
) -> c_int {
    catch_panic(0, || {
        let t = tx!(t);
        // SAFETY: C strings or null (caller contract).
        let (uri, protocol, http_version) = unsafe { (bytes(uri), bytes(protocol), bytes(http_version)) };
        t.process_uri(uri, protocol, http_version);
        1
    })
}

/// # Safety
/// As above.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_process_request_headers(t: *mut CTransaction) -> c_int {
    catch_panic(0, || {
        tx!(t).process_request_headers();
        1
    })
}

/// # Safety
/// As above.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_process_request_body(t: *mut CTransaction) -> c_int {
    catch_panic(0, || {
        tx!(t).process_request_body();
        1
    })
}

/// # Safety
/// As above; `buf` points to `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_append_request_body(t: *mut CTransaction, buf: *const c_uchar, len: usize) -> c_int {
    catch_panic(0, || {
        let t = tx!(t);
        // SAFETY: `buf` points to `len` bytes, or is null (caller contract).
        let buf = unsafe { slice(buf, len) };
        c_int::from(t.append_request_body(buf))
    })
}

/// # Safety
/// As above.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_request_body_from_file(t: *mut CTransaction, path: *const c_char) -> c_int {
    catch_panic(0, || {
        let t = tx!(t);
        // SAFETY: a C string or null (caller contract).
        let p = String::from_utf8_lossy(unsafe { bytes(path) });
        // 0 when the file cannot be read.
        t.request_body_from_file(&p).map_or(0, c_int::from)
    })
}

/// # Safety
/// As above.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_process_response_headers(
    t: *mut CTransaction,
    code: c_int,
    protocol: *const c_char,
) -> c_int {
    catch_panic(0, || {
        let t = tx!(t);
        // SAFETY: a C string or null (caller contract).
        let p = String::from_utf8_lossy(unsafe { bytes(protocol) });
        t.process_response_headers(u16::try_from(code).unwrap_or(0), &p);
        1
    })
}

/// # Safety
/// As above.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_process_response_body(t: *mut CTransaction) -> c_int {
    catch_panic(0, || {
        tx!(t).process_response_body();
        1
    })
}

/// # Safety
/// As above; `buf` points to `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_append_response_body(t: *mut CTransaction, buf: *const c_uchar, len: usize) -> c_int {
    catch_panic(0, || {
        let t = tx!(t);
        // SAFETY: `buf` points to `len` bytes, or is null (caller contract).
        let buf = unsafe { slice(buf, len) };
        c_int::from(t.append_response_body(buf))
    })
}

/// # Safety
/// As above; `key`/`value` are C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_add_request_header(
    t: *mut CTransaction,
    key: *const c_uchar,
    value: *const c_uchar,
) -> c_int {
    catch_panic(0, || {
        let t = tx!(t);
        // SAFETY: C strings or null (caller contract).
        let (key, value) = unsafe { (bytes(key as *const c_char), bytes(value as *const c_char)) };
        t.add_request_header(key, value);
        1
    })
}

/// # Safety
/// As above; `key`/`value` point to `len_*` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_add_n_request_header(
    t: *mut CTransaction,
    key: *const c_uchar,
    len_key: usize,
    value: *const c_uchar,
    len_value: usize,
) -> c_int {
    catch_panic(0, || {
        let t = tx!(t);
        // SAFETY: `key` and `value` point to `len_key` and `len_value`
        // bytes, or are null (caller contract).
        let (key, value) = unsafe { (slice(key, len_key), slice(value, len_value)) };
        t.add_request_header(key, value);
        1
    })
}

/// # Safety
/// As above; `key`/`value` are C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_add_response_header(
    t: *mut CTransaction,
    key: *const c_uchar,
    value: *const c_uchar,
) -> c_int {
    catch_panic(0, || {
        let t = tx!(t);
        // SAFETY: C strings or null (caller contract).
        let (key, value) = unsafe { (bytes(key as *const c_char), bytes(value as *const c_char)) };
        t.add_response_header(key, value);
        1
    })
}

/// # Safety
/// As above; `key`/`value` point to `len_*` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_add_n_response_header(
    t: *mut CTransaction,
    key: *const c_uchar,
    len_key: usize,
    value: *const c_uchar,
    len_value: usize,
) -> c_int {
    catch_panic(0, || {
        let t = tx!(t);
        // SAFETY: `key` and `value` point to `len_key` and `len_value`
        // bytes, or are null (caller contract).
        let (key, value) = unsafe { (slice(key, len_key), slice(value, len_value)) };
        t.add_response_header(key, value);
        1
    })
}

/// # Safety
/// `t` must come from `msc_new_transaction*` and not be used after.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_transaction_cleanup(t: *mut CTransaction) {
    catch_panic((), || {
        if !t.is_null() {
            // SAFETY: `t` is the box `msc_new_transaction*` leaked, released
            // once (caller contract).
            drop(unsafe { Box::from_raw(t) });
        }
    })
}

/// # Safety
/// `t` as above; `it` points to a valid intervention struct.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_intervention(t: *mut CTransaction, it: *mut ModSecurityIntervention) -> c_int {
    catch_panic(0, || {
        let t = tx!(t);
        // SAFETY: valid out-pointer per contract.
        let Some(it) = (unsafe { it.as_mut() }) else {
            return 0;
        };
        if let Some(pending) = t.intervention() {
            it.fill_from(&pending);
        }
        // The C API returns the caller's field (filled above when there was one).
        it.disruptive
    })
}

/// # Safety
/// `it` points to an intervention filled by `msc_intervention`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_intervention_cleanup(it: *mut ModSecurityIntervention) {
    catch_panic((), || {
        // SAFETY: null or a valid intervention struct (caller contract).
        if let Some(it) = unsafe { it.as_mut() } {
            it.free_and_clean();
        }
    })
}

/// # Safety
/// `t` as above. The returned string is `malloc`ed (free with `free`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_get_response_body(t: *const CTransaction) -> *const c_char {
    catch_panic(ptr::null(), || {
        // SAFETY: live transaction per contract.
        let Some(t) = (unsafe { t.as_ref() }) else {
            return ptr::null();
        };
        // A C string: the raw bytes of the body up to the first NUL byte.
        intervention::strdup(t.response_body())
    })
}

/// # Safety
/// `t` as above.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_get_response_body_length(t: *mut CTransaction) -> usize {
    catch_panic(0, || tx!(t).response_body_length())
}

/// # Safety
/// `t` as above.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_get_request_body_length(t: *mut CTransaction) -> usize {
    catch_panic(0, || tx!(t).request_body_length())
}

/// # Safety
/// `t` as above.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_process_logging(t: *mut CTransaction) -> c_int {
    catch_panic(0, || {
        tx!(t).process_logging();
        1
    })
}

/// # Safety
/// `t` as above.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_update_status_code(t: *mut CTransaction, status: c_int) -> c_int {
    catch_panic(0, || {
        // A number that is not a status code is recorded as 0.
        tx!(t).update_status_code(u16::try_from(status).unwrap_or(0));
        1
    })
}

/// # Safety
/// `t` as above; `hostname` is a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_set_request_hostname(t: *mut CTransaction, hostname: *const c_uchar) -> c_int {
    catch_panic(0, || {
        let t = tx!(t);
        // SAFETY: a C string or null (caller contract).
        let h = String::from_utf8_lossy(unsafe { bytes(hostname as *const c_char) });
        t.set_request_host_name(&h);
        1
    })
}

/// # Safety
/// `t` as above.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_get_rules_messages_size(t: *const CTransaction) -> usize {
    catch_panic(0, || {
        // SAFETY: live transaction per contract.
        unsafe { t.as_ref() }.map(|t| t.rule_messages().len()).unwrap_or(0)
    })
}

/// # Safety
/// `t` as above; `ids` points to `ids_len` writable slots.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_get_rules_messages_rule_ids(
    t: *const CTransaction,
    ids: *mut i64,
    ids_len: usize,
) -> usize {
    catch_panic(0, || {
        // SAFETY: live transaction per contract.
        let Some(t) = (unsafe { t.as_ref() }) else {
            return 0;
        };
        if ids.is_null() || ids_len == 0 {
            return 0;
        }
        let mut written = 0;
        for m in t.rule_messages() {
            if written >= ids_len {
                break;
            }
            // SAFETY: written < ids_len, within the caller's buffer.
            unsafe { *ids.add(written) = i64::try_from(m.rule_id()).unwrap_or(i64::MAX) };
            written += 1;
        }
        written
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_transaction_needs_an_engine_and_rules() {
        let ms = crate::modsecurity::msc_init();
        let rules = crate::rules_set::msc_create_rules_set();
        // SAFETY: valid or null pointers; what is created is released.
        unsafe {
            assert!(msc_new_transaction(ptr::null_mut(), rules, ptr::null_mut()).is_null());
            assert!(msc_new_transaction(ms, ptr::null_mut(), ptr::null_mut()).is_null());
            assert!(msc_new_transaction_with_id(ptr::null_mut(), rules, c"id".as_ptr(), ptr::null_mut()).is_null());
            assert!(msc_new_transaction_with_id(ms, ptr::null_mut(), c"id".as_ptr(), ptr::null_mut()).is_null());
            let t = msc_new_transaction_with_id(ms, rules, c"id".as_ptr(), ptr::null_mut());
            assert!(!t.is_null());
            msc_transaction_cleanup(t);
            crate::rules_set::msc_rules_cleanup(rules);
            crate::modsecurity::msc_cleanup(ms);
        }
    }
}
