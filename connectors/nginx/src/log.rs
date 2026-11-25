//! The log phase handler.

use nginx_sys::{NGX_ERROR, NGX_OK, ngx_http_request_t, ngx_int_t};

use crate::context::Ctx;
use crate::nginx::{Request, catch_panic};

/// The logging step shared by the log phase handler and early logging on
/// interventions.
pub fn process_logging(ctx: &mut Ctx) {
    ctx.modsec_transaction.process_logging();
}

/// The log phase handler: logs the transaction, unless an intervention
/// already did.
///
/// # Safety
/// Called by nginx (log phase) with a valid request.
pub unsafe extern "C" fn ngx_http_modsecurity_log_handler(r: *mut ngx_http_request_t) -> ngx_int_t {
    // SAFETY: nginx calls the handler with a valid request.
    let Some(request) = (unsafe { Request::new(r) }) else {
        return NGX_OK as ngx_int_t;
    };
    catch_panic(
        request.log(),
        "the log handler",
        || NGX_ERROR as ngx_int_t,
        || {
            // SAFETY: the context lives until the request pool is destroyed,
            // and nothing else uses it while this handler runs.
            if let Some(ctx) = unsafe { Ctx::find(&request).as_mut() }
                && !ctx.logged
            {
                process_logging(ctx);
            }
            NGX_OK as ngx_int_t
        },
    )
}
