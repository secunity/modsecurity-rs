//! Port of `src/ngx_http_modsecurity_log.c`: the libmodsecurity log
//! callback and the log phase handler.

use nginx_sys::{NGX_LOG_INFO, NGX_OK, ngx_http_request_t, ngx_int_t, ngx_log_t, ngx_uint_t};

use crate::ngx_http_modsecurity_common::{Ctx, log_error};
use crate::ngx_http_modsecurity_module::ngx_http_modsecurity_get_module_ctx;

/// `ngx_http_modsecurity_log`: libmodsecurity's server log callback; writes
/// the rule message to the request's error log at `info` level.
///
/// # Safety
/// `log` must be null or a valid nginx log.
pub unsafe fn ngx_http_modsecurity_log(log: *mut ngx_log_t, msg: &str) {
    if log.is_null() {
        return;
    }
    // SAFETY: valid log per the contract.
    unsafe { log_error(NGX_LOG_INFO as ngx_uint_t, log, msg.as_bytes()) };
}

/// The logging step shared by the log phase handler and early logging on
/// interventions (`msc_process_logging`).
pub fn process_logging(ctx: &mut Ctx) {
    ctx.modsec_transaction.process_logging();
}

/// `ngx_http_modsecurity_log_handler`
///
/// # Safety
/// Called by nginx (log phase) with a valid request.
pub unsafe extern "C" fn ngx_http_modsecurity_log_handler(r: *mut ngx_http_request_t) -> ngx_int_t {
    // SAFETY: called by nginx in the log phase with a valid request.
    let ctx = unsafe { ngx_http_modsecurity_get_module_ctx(r) };
    if ctx.is_null() {
        return NGX_OK as ngx_int_t;
    }
    // SAFETY: the context lives until the request pool is destroyed.
    let ctx = unsafe { &mut *ctx };
    if ctx.logged {
        return NGX_OK as ngx_int_t;
    }
    process_logging(ctx);
    NGX_OK as ngx_int_t
}
