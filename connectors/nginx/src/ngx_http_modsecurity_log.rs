//! The log phase handler.

use nginx_sys::{NGX_OK, ngx_http_request_t, ngx_int_t};

use crate::nginx::Request;
use crate::ngx_http_modsecurity_common::Ctx;

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
    // SAFETY: nginx calls the handler with a valid request; its context
    // lives until the request pool is destroyed, and nothing else uses it
    // while this handler runs.
    let ctx = unsafe { Request::new(r).and_then(|request| Ctx::find(&request).as_mut()) };
    if let Some(ctx) = ctx
        && !ctx.logged
    {
        process_logging(ctx);
    }
    NGX_OK as ngx_int_t
}
