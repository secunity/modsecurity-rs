//! The body filter, which feeds the response body to ModSecurity.

use core::ptr;

use nginx_sys::{
    NGX_HTTP_INTERNAL_SERVER_ERROR, ngx_chain_t, ngx_http_output_body_filter_pt, ngx_http_request_t,
    ngx_http_top_body_filter, ngx_int_t,
};

use crate::context::Ctx;
use crate::intervention::process_intervention;
use crate::module::ngx_http_modsecurity_module;
use crate::nginx::{Buffers, Request};

static mut NGX_HTTP_NEXT_BODY_FILTER: ngx_http_output_body_filter_pt = None;

/// `ngx_http_modsecurity_body_filter_init`
///
/// XXX (C): check behaviour on few body filters installed
///
/// # Safety
/// Called once from postconfiguration.
pub unsafe fn ngx_http_modsecurity_body_filter_init() -> ngx_int_t {
    // SAFETY: nginx configures filters single-threaded.
    unsafe {
        NGX_HTTP_NEXT_BODY_FILTER = ngx_http_top_body_filter;
        ngx_http_top_body_filter = Some(ngx_http_modsecurity_body_filter);
    }
    nginx_sys::NGX_OK as ngx_int_t
}

/// What the filter does with the chain once ModSecurity has seen it.
enum Outcome {
    /// Pass it to the next filter.
    Pass,
    /// Return this to nginx.
    Return(ngx_int_t),
    /// End the request with this status.
    Finalize(ngx_int_t),
}

/// Sanity checks (`MODSECURITY_SANITY_CHECKS`): the number of response
/// headers that were not inspected by ModSecurity.
#[cfg(feature = "sanity-checks")]
fn headers_not_inspected(request: &Request<'_>, ctx: &Ctx) -> usize {
    let mut worth_to_fail = 0;
    request.for_each_header_out(|name, value| {
        let found = ctx.sanity_headers_out.iter().any(|h| name == h.name.as_slice() && value == h.value.as_slice());
        if !found {
            worth_to_fail += 1;
        }
    });
    worth_to_fail
}

/// Gives the buffers of the response body to ModSecurity, and runs its
/// response body phase after the last one.
fn inspect_body(request: &Request<'_>, ctx: &mut Ctx, buffers: Buffers<'_>) -> Outcome {
    #[cfg(feature = "sanity-checks")]
    {
        let enabled = crate::context::loc_conf(request)
            .is_some_and(|conf| conf.sanity_checks_enabled != nginx_sys::NGX_CONF_UNSET as nginx_sys::ngx_flag_t);
        if enabled && headers_not_inspected(request, ctx) > 0 {
            return Outcome::Finalize(NGX_HTTP_INTERNAL_SERVER_ERROR as ngx_int_t);
        }
    }

    for buffer in buffers {
        ctx.modsec_transaction.append_response_body(buffer.data);
        let ret = process_intervention(ctx, request, false);
        if ret > 0 {
            return Outcome::Finalize(ret);
        }

        // XXX (C): chain->buf->last_buf || chain->buf->last_in_chain
        if buffer.last {
            ctx.modsec_transaction.process_response_body();

            // XXX (C): I don't get how body from modsec being transferred
            // to nginx's buffer. If so - after adjusting of nginx's body we
            // can proceed to adjust body size (content-length). see
            // xslt_body_filter() for example
            let ret = process_intervention(ctx, request, false);
            if ret > 0 {
                return Outcome::Return(ret);
            } else if ret < 0 {
                return Outcome::Finalize(NGX_HTTP_INTERNAL_SERVER_ERROR as ngx_int_t);
            }
        }
    }
    Outcome::Pass
}

/// `ngx_http_modsecurity_body_filter`
///
/// # Safety
/// Called by nginx with a valid request and output chain.
pub unsafe extern "C" fn ngx_http_modsecurity_body_filter(
    r: *mut ngx_http_request_t,
    input: *mut ngx_chain_t,
) -> ngx_int_t {
    let next = || {
        // SAFETY: the next filter was saved at init, and is given what
        // this filter was called with.
        unsafe {
            match NGX_HTTP_NEXT_BODY_FILTER {
                Some(f) => f(r, input),
                None => nginx_sys::NGX_OK as ngx_int_t,
            }
        }
    };
    // SAFETY: nginx calls the filter with a valid request.
    let Some(request) = (unsafe { Request::new(r) }) else {
        return nginx_sys::NGX_ERROR as ngx_int_t;
    };
    if input.is_null() {
        return next();
    }
    // SAFETY: the context lives until the request pool is destroyed, and
    // nothing else uses it while this filter inspects the body.
    let ctx = match unsafe { Ctx::find(&request).as_mut() } {
        Some(ctx) if !ctx.intervention_triggered => ctx,
        _ => return next(),
    };

    // SAFETY: nginx's chain, unchanged until it is passed on below.
    let buffers = unsafe { Buffers::new(input) };
    match inspect_body(&request, ctx, buffers) {
        // XXX (C): xflt_filter() -- return NGX_OK here
        Outcome::Pass => next(),
        Outcome::Return(rc) => rc,
        // SAFETY: this filter belongs to this module.
        Outcome::Finalize(rc) => unsafe {
            request.finalize_from_filter(ptr::addr_of_mut!(ngx_http_modsecurity_module), rc)
        },
    }
}
