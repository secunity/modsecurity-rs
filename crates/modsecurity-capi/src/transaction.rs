//! The libmodsecurity C API for transactions (`msc_new_transaction`, ...).

use crate::intervention::{self, ModSecurityIntervention};
use crate::modsecurity::CLogData;
use engine::ModSecurity;
use engine::RulesSet;
use engine::Transaction;
use std::ffi::{CStr, c_char, c_int, c_uchar, c_void};

/// The C API hands out transactions without a lifetime; the connector
/// guarantees the `ModSecurity` and `RulesSet` outlive them.
pub type CTransaction = Transaction<'static>;

unsafe fn bytes<'a>(p: *const c_char) -> &'a [u8] {
    if p.is_null() {
        return b"";
    }
    // SAFETY: C API contract: NUL terminated strings.
    unsafe { CStr::from_ptr(p) }.to_bytes()
}

unsafe fn slice<'a>(p: *const c_uchar, len: usize) -> &'a [u8] {
    if p.is_null() || len == 0 {
        return b"";
    }
    // SAFETY: C API contract: `p` points to `len` readable bytes.
    unsafe { std::slice::from_raw_parts(p, len) }
}

/// # Safety
/// `ms` and `rules` must be valid and outlive the transaction.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_new_transaction(
    ms: *mut ModSecurity,
    rules: *mut RulesSet,
    log_cb_data: *mut c_void,
) -> *mut CTransaction {
    // SAFETY: see the function contract.
    let (ms, rules): (&'static ModSecurity, &'static RulesSet) = unsafe { (&*ms, &*rules) };
    Box::into_raw(Box::new(Transaction::new(ms, rules, Some(Box::new(CLogData(log_cb_data))))))
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
    // SAFETY: see the function contract.
    let (ms, rules): (&'static ModSecurity, &'static RulesSet) = unsafe { (&*ms, &*rules) };
    let id = String::from_utf8_lossy(unsafe { bytes(id) }).into_owned();
    Box::into_raw(Box::new(Transaction::with_id(ms, rules, &id, Some(Box::new(CLogData(log_cb_data))))))
}

macro_rules! tx {
    ($t:expr) => {
        // SAFETY: the C API contract: a live transaction pointer.
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
    let t = tx!(t);
    let c = String::from_utf8_lossy(unsafe { bytes(client) }).into_owned();
    let s = String::from_utf8_lossy(unsafe { bytes(server) }).into_owned();
    t.process_connection(&c, c_port, &s, s_port);
    1
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
    let t = tx!(t);
    t.process_uri(unsafe { bytes(uri) }, unsafe { bytes(protocol) }, unsafe { bytes(http_version) });
    1
}

/// # Safety
/// As above.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_process_request_headers(t: *mut CTransaction) -> c_int {
    tx!(t).process_request_headers();
    1
}

/// # Safety
/// As above.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_process_request_body(t: *mut CTransaction) -> c_int {
    tx!(t).process_request_body();
    1
}

/// # Safety
/// As above; `buf` points to `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_append_request_body(t: *mut CTransaction, buf: *const c_uchar, len: usize) -> c_int {
    c_int::from(tx!(t).append_request_body(unsafe { slice(buf, len) }))
}

/// # Safety
/// As above.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_request_body_from_file(t: *mut CTransaction, path: *const c_char) -> c_int {
    let t = tx!(t);
    let p = String::from_utf8_lossy(unsafe { bytes(path) }).into_owned();
    // 0 when the file cannot be read.
    t.request_body_from_file(&p).map_or(0, c_int::from)
}

/// # Safety
/// As above.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_process_response_headers(
    t: *mut CTransaction,
    code: c_int,
    protocol: *const c_char,
) -> c_int {
    let t = tx!(t);
    let p = String::from_utf8_lossy(unsafe { bytes(protocol) }).into_owned();
    t.process_response_headers(code, &p);
    1
}

/// # Safety
/// As above.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_process_response_body(t: *mut CTransaction) -> c_int {
    tx!(t).process_response_body();
    1
}

/// # Safety
/// As above; `buf` points to `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_append_response_body(t: *mut CTransaction, buf: *const c_uchar, len: usize) -> c_int {
    c_int::from(tx!(t).append_response_body(unsafe { slice(buf, len) }))
}

/// # Safety
/// As above; `key`/`value` are C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_add_request_header(
    t: *mut CTransaction,
    key: *const c_uchar,
    value: *const c_uchar,
) -> c_int {
    let t = tx!(t);
    t.add_request_header(unsafe { bytes(key as *const c_char) }, unsafe { bytes(value as *const c_char) });
    1
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
    let t = tx!(t);
    t.add_request_header(unsafe { slice(key, len_key) }, unsafe { slice(value, len_value) });
    1
}

/// # Safety
/// As above; `key`/`value` are C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_add_response_header(
    t: *mut CTransaction,
    key: *const c_uchar,
    value: *const c_uchar,
) -> c_int {
    let t = tx!(t);
    t.add_response_header(unsafe { bytes(key as *const c_char) }, unsafe { bytes(value as *const c_char) });
    1
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
    let t = tx!(t);
    t.add_response_header(unsafe { slice(key, len_key) }, unsafe { slice(value, len_value) });
    1
}

/// # Safety
/// `t` must come from `msc_new_transaction*` and not be used after.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_transaction_cleanup(t: *mut CTransaction) {
    if !t.is_null() {
        drop(unsafe { Box::from_raw(t) });
    }
}

/// # Safety
/// `t` as above; `it` points to a valid intervention struct.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_intervention(t: *mut CTransaction, it: *mut ModSecurityIntervention) -> c_int {
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
}

/// # Safety
/// `it` points to an intervention filled by `msc_intervention`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_intervention_cleanup(it: *mut ModSecurityIntervention) {
    if let Some(it) = unsafe { it.as_mut() } {
        it.free_and_clean();
    }
}

/// # Safety
/// `t` as above. The returned string is `malloc`ed (free with `free`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_get_response_body(t: *const CTransaction) -> *const c_char {
    // SAFETY: live transaction per contract.
    let Some(t) = (unsafe { t.as_ref() }) else {
        return std::ptr::null();
    };
    // A C string: the raw bytes of the body up to the first NUL byte.
    intervention::strdup(t.response_body())
}

/// # Safety
/// `t` as above.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_get_response_body_length(t: *mut CTransaction) -> usize {
    tx!(t).response_body_length()
}

/// # Safety
/// `t` as above.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_get_request_body_length(t: *mut CTransaction) -> usize {
    tx!(t).request_body_length()
}

/// # Safety
/// `t` as above.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_process_logging(t: *mut CTransaction) -> c_int {
    tx!(t).process_logging();
    1
}

/// # Safety
/// `t` as above.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_update_status_code(t: *mut CTransaction, status: c_int) -> c_int {
    tx!(t).update_status_code(status);
    1
}

/// # Safety
/// `t` as above; `hostname` is a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_set_request_hostname(t: *mut CTransaction, hostname: *const c_uchar) -> c_int {
    let t = tx!(t);
    let h = String::from_utf8_lossy(unsafe { bytes(hostname as *const c_char) }).into_owned();
    t.set_request_host_name(&h);
    1
}

/// # Safety
/// `t` as above.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_get_rules_messages_size(t: *const CTransaction) -> usize {
    // SAFETY: live transaction per contract.
    unsafe { t.as_ref() }.map(|t| t.rule_messages().len()).unwrap_or(0)
}

/// # Safety
/// `t` as above; `ids` points to `ids_len` writable slots.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msc_get_rules_messages_rule_ids(
    t: *const CTransaction,
    ids: *mut i64,
    ids_len: usize,
) -> usize {
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
}
