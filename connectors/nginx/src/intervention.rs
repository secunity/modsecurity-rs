//! Applying an intervention of ModSecurity to the request.

use nginx_sys::{NGX_HTTP_INTERNAL_SERVER_ERROR, NGX_LOG_ERR, ngx_int_t, ngx_uint_t};

use crate::context::{Ctx, loc_conf};
use crate::log::process_logging;
use crate::nginx::Request;

/// Applies a pending intervention to the request
/// (`ngx_http_modsecurity_process_intervention`). Returns the HTTP status
/// to finalize with (> 0), 0 when there is nothing to do, or -1 when the
/// response headers were already sent.
///
/// With `early_log`, the transaction is logged right away when the
/// intervention has a status other than 200 and no redirection: nginx may
/// not reach the log phase for it.
pub fn process_intervention(ctx: &mut Ctx, request: &Request<'_>, early_log: bool) -> ngx_int_t {
    let Some(it) = ctx.modsec_transaction.intervention() else {
        return 0;
    };

    let Some(conf) = loc_conf(request) else {
        return NGX_HTTP_INTERNAL_SERVER_ERROR as ngx_int_t;
    };

    // `modsecurity_use_error_log off` keeps the intervention out of the
    // nginx error log.
    if conf.use_error_log != 0 {
        let log = it.log.as_bytes();
        request.log().error(NGX_LOG_ERR as ngx_uint_t, log);
    }

    // The C connector reads the url as a C string: up to its first NUL.
    let url = it.url.as_deref().map(crate::nginx::c_str);
    let status = it.status;

    if let Some(url) = url {
        if request.header_sent() {
            return -1;
        }
        let Some(_location) = request.set_location(url) else {
            return NGX_HTTP_INTERNAL_SERVER_ERROR as ngx_int_t;
        };
        #[cfg(feature = "sanity-checks")]
        crate::header_filter::store_header(ctx, _location.0, _location.1);
        return status as ngx_int_t;
    }

    if status != 200 {
        // Records the status for the audit log, which would otherwise lack
        // it when, for example, an `error_page` redirect follows. The rest of
        // that response, such as its headers, still does not reach it.
        ctx.modsec_transaction.update_status_code(status);

        if early_log {
            process_logging(ctx);
            ctx.logged = true;
        }

        if request.header_sent() {
            return -1;
        }
        return status as ngx_int_t;
    }
    0
}
