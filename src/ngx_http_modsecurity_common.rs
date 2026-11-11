//! Port of `src/ngx_http_modsecurity_common.h`: versions, the per-request
//! context and the module configuration structures.

use core::ffi::c_void;

use modsecurity::modsecurity::ModSecurity;
use modsecurity::rules_set::RulesSet;
use modsecurity::transaction::Transaction;
use nginx_sys::{
    ngx_flag_t, ngx_http_complex_value_t, ngx_http_request_t, ngx_log_error_core, ngx_log_t, ngx_pool_t, ngx_uint_t,
};

/// TAG_NUM:
///
/// Alpha  - 001
/// Beta   - 002
/// Dev    - 010
/// Rc1    - 051
/// Rc2    - 052
/// ...    - ...
/// Release- 100
pub const MODSECURITY_NGINX_MAJOR: &str = "1";
pub const MODSECURITY_NGINX_MINOR: &str = "0";
pub const MODSECURITY_NGINX_PATCHLEVEL: &str = "4";
pub const MODSECURITY_NGINX_TAG: &str = "";
pub const MODSECURITY_NGINX_TAG_NUM: &str = "100";
pub const MODSECURITY_NGINX_VERSION: &str = "1.0.4";
pub const MODSECURITY_NGINX_VERSION_NUM: &str = "104100";
pub const MODSECURITY_NGINX_WHOAMI: &str = "ModSecurity-nginx v1.0.4";

/// `ngx_http_modsecurity_header_t` (sanity checks): a header sent to
/// ModSecurity.
#[cfg(feature = "sanity-checks")]
pub struct Header {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

/// `ngx_http_modsecurity_ctx_t`: per-request state.
///
/// The C struct is allocated from the request pool and its transaction is
/// freed by a pool cleanup; here the context is boxed and the same pool
/// cleanup drops it (see `create_ctx`).
pub struct Ctx {
    pub r: *mut ngx_http_request_t,
    pub modsec_transaction: Transaction<'static>,
    /// Should be filled with the headers that were sent to ModSecurity.
    ///
    /// The idea is to compare this set of headers with the headers that were
    /// sent to the client. This check was placed because we don't have
    /// control over other modules, thus, we may partially inspect the
    /// headers.
    #[cfg(feature = "sanity-checks")]
    pub sanity_headers_out: Vec<Header>,
    pub waiting_more_body: bool,
    pub body_requested: bool,
    pub processed: bool,
    pub logged: bool,
    pub intervention_triggered: bool,
    pub request_body_processed: bool,
}

/// `ngx_http_modsecurity_main_conf_t`
pub struct MainConf {
    pub pool: *mut ngx_pool_t,
    pub modsec: ModSecurity,
    pub rules_inline: ngx_uint_t,
    pub rules_file: ngx_uint_t,
    pub rules_remote: ngx_uint_t,
}

/// `ngx_http_modsecurity_conf_t`: per-location configuration. The flags are
/// `ngx_flag_t` so that nginx's `ngx_conf_set_flag_slot` sets them (and
/// reports errors) exactly as for the C module.
pub struct LocConf {
    pub pool: *mut ngx_pool_t,
    pub rules_set: RulesSet,
    pub enable: ngx_flag_t,
    pub use_error_log: ngx_flag_t,
    #[cfg(feature = "sanity-checks")]
    pub sanity_checks_enabled: ngx_flag_t,
    pub transaction_id: *mut ngx_http_complex_value_t,
}

/// The connector's per-transaction log callback data: the request's
/// connection log (`r->connection->log`), as in C.
pub struct NgxLog(pub *mut ngx_log_t);

// SAFETY: the pointer is only dereferenced on the worker thread that owns
// the request (libmodsecurity calls the log callback synchronously from the
// transaction methods the connector invokes); `Send` is only needed because
// the transaction's callback data must be `Send`.
unsafe impl Send for NgxLog {}

/// `ngx_log_error(level, log, 0, "%s", msg)`: logs a byte string through
/// nginx (truncated at the first NUL, like the C string it replaces).
///
/// # Safety
/// `log` must be a valid nginx log.
pub unsafe fn log_error(level: ngx_uint_t, log: *mut ngx_log_t, msg: &[u8]) {
    // SAFETY: valid log per the contract.
    if log.is_null() || level > unsafe { (*log).log_level } {
        return;
    }
    let end = msg.iter().position(|&c| c == 0).unwrap_or(msg.len());
    let mut c = Vec::with_capacity(end + 1);
    c.extend_from_slice(&msg[..end]);
    c.push(0);
    // SAFETY: "%s" with one NUL terminated string argument.
    unsafe { ngx_log_error_core(level, log, 0, c"%s".as_ptr(), c.as_ptr() as *const c_void) };
}
