//! The access phase handler, which feeds the connection, the request line,
//! the request headers and the request body to ModSecurity.

use nginx_sys::{
    NGX_AGAIN, NGX_DECLINED, NGX_DONE, NGX_ERROR, NGX_HTTP_INTERNAL_SERVER_ERROR, NGX_HTTP_SPECIAL_RESPONSE,
    ngx_http_request_t, ngx_int_t,
};

use crate::context::{Ctx, loc_conf};
use crate::intervention::process_intervention;
use crate::nginx::Request;

/// Post handler of `ngx_http_read_client_request_body`; resumes the phases
/// once the body is read (`ngx_http_modsecurity_request_read`).
///
/// # Safety
/// Called by nginx with a valid request.
pub unsafe extern "C" fn ngx_http_modsecurity_request_read(r: *mut ngx_http_request_t) {
    // SAFETY: nginx calls the handler with a valid request.
    let Some(request) = (unsafe { Request::new(r) }) else {
        return;
    };
    let ctx = Ctx::find(&request);

    request.release_body_reference();

    // SAFETY: the context lives until the request pool is destroyed. No
    // reference to it is held here: the access handler may be the caller
    // (when the body was already read), and it is the next one to run.
    unsafe {
        if !ctx.is_null() && (*ctx).waiting_more_body {
            (*ctx).waiting_more_body = false;
            request.run_phases_on_write();
            request.run_phases();
        }
    }
}

/// Connection, URI and request header processing (done once, when the
/// context is created). Returns `Some(status)` when the handler must
/// return immediately.
fn process_request_line_and_headers(request: &Request<'_>, ctx: &mut Ctx) -> Option<ngx_int_t> {
    // FIXME (C): We may want to use struct sockaddr instead of addr_text.
    //
    // FIXME (C): Check if it is possible to hook on nginx on a earlier
    // phase. At this point we are doing an late connection process. Maybe
    // we have to hook into NGX_HTTP_FIND_CONFIG_PHASE, it seems to be the
    // erliest phase that nginx allow us to attach those kind of hooks.
    let client_port = request.client_port();
    let server_port = request.server_port();
    let client_addr = String::from_utf8_lossy(&request.client_addr()).into_owned();

    if let Some(hostname) = request.host_name() {
        // set the hostname in the transaction (ModSecurity >= 3.0.13)
        ctx.modsec_transaction.set_request_host_name(&String::from_utf8_lossy(&hostname));
    }

    let Some(server_addr) = request.server_addr() else {
        return Some(NGX_HTTP_INTERNAL_SERVER_ERROR as ngx_int_t);
    };
    let server_addr = String::from_utf8_lossy(&server_addr).into_owned();

    ctx.modsec_transaction.process_connection(&client_addr, client_port, &server_addr, server_port);

    // FIXME (C): Check how we can finalize a request without crash nginx.
    // I don't think nginx is expecting to finalize a request at that point
    // as it seems that it clean the ngx_http_request_t information and try
    // to use it later.
    let ret = process_intervention(ctx, request, true);
    if ret > 0 {
        ctx.intervention_triggered = true;
        return Some(ret);
    }

    let http_version = request.http_version();
    let uri = request.unparsed_uri();
    let method = request.method_name();
    if uri.is_empty() {
        return Some(NGX_HTTP_INTERNAL_SERVER_ERROR as ngx_int_t);
    }

    ctx.modsec_transaction.process_uri(&uri, &method, &http_version);
    let ret = process_intervention(ctx, request, true);
    if ret > 0 {
        ctx.intervention_triggered = true;
        return Some(ret);
    }

    // Since incoming request headers are already in place, lets send it to
    // ModSecurity.
    request.for_each_header_in(|name, value| ctx.modsec_transaction.add_request_header(name, value));

    // Since ModSecurity already knew about all headers, i guess it is safe
    // to process this information.
    ctx.modsec_transaction.process_request_headers();
    let ret = process_intervention(ctx, request, true);
    if request.error_page() {
        return Some(NGX_DECLINED as ngx_int_t);
    }
    if ret > 0 {
        ctx.intervention_triggered = true;
        return Some(ret);
    }
    None
}

/// What the access handler does next for a request.
enum Next {
    Return(ngx_int_t),
    /// Ask nginx for the request body.
    ReadBody,
    /// The body is read: give it to ModSecurity.
    InspectBody,
}

fn next_step(ctx: &mut Ctx) -> Next {
    if ctx.request_body_processed {
        // should we use r->internal or r->filter_finalize?
        return Next::Return(NGX_DECLINED as ngx_int_t);
    }
    if ctx.intervention_triggered {
        return Next::Return(NGX_DECLINED as ngx_int_t);
    }
    if ctx.waiting_more_body {
        return Next::Return(NGX_DONE as ngx_int_t);
    }
    if ctx.body_requested {
        return Next::InspectBody;
    }
    ctx.body_requested = true;
    Next::ReadBody
}

/// Gives the request body to ModSecurity and runs its request body phase.
fn inspect_body(request: &Request<'_>, ctx: &mut Ctx) -> ngx_int_t {
    request.run_phases_on_write();

    // TODO (C): Speed up the analysis by sending chunk while they arrive.
    // Notice that we are waiting for the full request body to start to
    // process it.
    if let Some(file_name) = request.body_file() {
        // Request body was saved to a file, probably we don't have a copy
        // of it in memory.
        //
        // The C module ignores the result too; libmodsecurity logs a file
        // it cannot read.
        let _ = ctx.modsec_transaction.request_body_from_file(&String::from_utf8_lossy(&file_name));
    } else {
        for buffer in request.body_buffers() {
            ctx.modsec_transaction.append_request_body(buffer.data);
            if buffer.last {
                break;
            }

            // XXX (C): chains are processed one-by-one, maybe worth to pass
            // all chains and then call intervention() ?
            //
            // ModSecurity may perform stream inspection on this buffer, it
            // may ask for a intervention in consequence of that.
            let ret = process_intervention(ctx, request, false);
            if ret > 0 {
                return ret;
            }
        }
    }

    // At this point, all the request body was sent to ModSecurity and we
    // want to make sure that all the request body inspection happened;
    // consequently we have to check if ModSecurity have returned any kind
    // of intervention.
    ctx.modsec_transaction.process_request_body();
    ctx.request_body_processed = true;

    let ret = process_intervention(ctx, request, false);
    if request.error_page() {
        return NGX_DECLINED as ngx_int_t;
    }
    if ret > 0 {
        return ret;
    }
    NGX_DECLINED as ngx_int_t
}

/// `ngx_http_modsecurity_access_handler`
///
/// # Safety
/// Called by nginx (access phase) with a valid request.
pub unsafe extern "C" fn ngx_http_modsecurity_access_handler(r: *mut ngx_http_request_t) -> ngx_int_t {
    // SAFETY: nginx calls the handler with a valid request.
    let Some(request) = (unsafe { Request::new(r) }) else {
        return NGX_DECLINED as ngx_int_t;
    };
    if loc_conf(&request).is_none_or(|conf| conf.enable != 1) {
        return NGX_DECLINED as ngx_int_t;
    }

    let mut ctx = Ctx::find(&request);
    if ctx.is_null() {
        ctx = Ctx::create(&request);
        // SAFETY: the context just made, which only this handler has.
        let Some(new) = (unsafe { ctx.as_mut() }) else {
            return NGX_HTTP_INTERNAL_SERVER_ERROR as ngx_int_t;
        };
        if let Some(rc) = process_request_line_and_headers(&request, new) {
            return rc;
        }
    }

    // SAFETY: the context lives until the request pool is destroyed. Each
    // reference to it below ends before nginx is asked for the body: that
    // can call `ngx_http_modsecurity_request_read`, which reads the context.
    match next_step(unsafe { &mut *ctx }) {
        Next::Return(rc) => return rc,
        Next::ReadBody => {
            let rc = request.read_body(Some(ngx_http_modsecurity_request_read));
            if rc == NGX_ERROR as ngx_int_t || rc >= NGX_HTTP_SPECIAL_RESPONSE as ngx_int_t {
                return rc;
            }
            if rc == NGX_AGAIN as ngx_int_t {
                // SAFETY: as above; nginx is done with the call.
                unsafe { (*ctx).waiting_more_body = true };
                return NGX_DONE as ngx_int_t;
            }
        }
        Next::InspectBody => {}
    }

    // SAFETY: as above.
    inspect_body(&request, unsafe { &mut *ctx })
}
