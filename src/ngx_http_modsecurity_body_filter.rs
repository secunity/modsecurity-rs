//! Port of `src/ngx_http_modsecurity_body_filter.c`: feeds the response body
//! to ModSecurity.

use core::ptr;

use nginx_sys::{
    NGX_HTTP_INTERNAL_SERVER_ERROR, ngx_chain_t, ngx_http_filter_finalize_request, ngx_http_output_body_filter_pt,
    ngx_http_request_t, ngx_http_top_body_filter, ngx_int_t,
};

use crate::ngx_http_modsecurity_module::{
    ngx_http_modsecurity_get_module_ctx, ngx_http_modsecurity_module, ngx_http_modsecurity_process_intervention,
};

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

unsafe fn next_body_filter(r: *mut ngx_http_request_t, chain: *mut ngx_chain_t) -> ngx_int_t {
    // SAFETY: the next filter was saved at init.
    unsafe {
        match NGX_HTTP_NEXT_BODY_FILTER {
            Some(f) => f(r, chain),
            None => nginx_sys::NGX_OK as ngx_int_t,
        }
    }
}

unsafe fn finalize(r: *mut ngx_http_request_t, rc: ngx_int_t) -> ngx_int_t {
    // SAFETY: valid request.
    unsafe { ngx_http_filter_finalize_request(r, ptr::addr_of_mut!(ngx_http_modsecurity_module), rc) }
}

/// Sanity checks (`MODSECURITY_SANITY_CHECKS`): identify a response header
/// that was not inspected by ModSecurity.
#[cfg(feature = "sanity-checks")]
unsafe fn headers_not_inspected(r: *mut ngx_http_request_t, ctx: &crate::ngx_http_modsecurity_common::Ctx) -> usize {
    let mut worth_to_fail = 0;
    // SAFETY: valid request.
    unsafe {
        crate::ngx_http_modsecurity_access::for_each_header(&(*r).headers_out.headers.part, |s1| {
            let found = ctx
                .sanity_headers_out
                .iter()
                .any(|h| s1.key.as_bytes() == h.name.as_slice() && s1.value.as_bytes() == h.value.as_slice());
            if !found {
                worth_to_fail += 1;
            }
        });
    }
    worth_to_fail
}

/// `ngx_http_modsecurity_body_filter`
///
/// # Safety
/// Called by nginx with a valid request and output chain.
pub unsafe extern "C" fn ngx_http_modsecurity_body_filter(
    r: *mut ngx_http_request_t,
    input: *mut ngx_chain_t,
) -> ngx_int_t {
    // SAFETY: called by nginx with a valid request and chain.
    unsafe {
        if input.is_null() {
            return next_body_filter(r, input);
        }
        let ctx = ngx_http_modsecurity_get_module_ctx(r);
        if ctx.is_null() {
            return next_body_filter(r, input);
        }
        let ctx = &mut *ctx;
        if ctx.intervention_triggered {
            return next_body_filter(r, input);
        }

        #[cfg(feature = "sanity-checks")]
        {
            let mcf = crate::ngx_http_modsecurity_module::loc_conf(r);
            if !mcf.is_null()
                && (*mcf).sanity_checks_enabled != nginx_sys::NGX_CONF_UNSET as nginx_sys::ngx_flag_t
                && headers_not_inspected(r, ctx) > 0
            {
                return finalize(r, NGX_HTTP_INTERNAL_SERVER_ERROR as ngx_int_t);
            }
        }

        let mut is_request_processed = false;
        let mut chain = input;
        while !chain.is_null() {
            let buf = (*chain).buf;
            let data = (*buf).pos;
            let len = (*buf).last.offset_from(data) as usize;
            let slice = if len == 0 || data.is_null() { &[][..] } else { core::slice::from_raw_parts(data, len) };
            ctx.modsec_transaction.append_response_body(slice);
            let ret = ngx_http_modsecurity_process_intervention(ctx, r, false);
            if ret > 0 {
                return finalize(r, ret);
            }

            // XXX (C): chain->buf->last_buf || chain->buf->last_in_chain
            is_request_processed = (*buf).last_buf() != 0;

            if is_request_processed {
                ctx.modsec_transaction.process_response_body();

                // XXX (C): I don't get how body from modsec being
                // transferred to nginx's buffer. If so - after adjusting of
                // nginx's body we can proceed to adjust body size
                // (content-length). see xslt_body_filter() for example
                let ret = ngx_http_modsecurity_process_intervention(ctx, r, false);
                if ret > 0 {
                    return ret;
                } else if ret < 0 {
                    return finalize(r, NGX_HTTP_INTERNAL_SERVER_ERROR as ngx_int_t);
                }
            }
            chain = (*chain).next;
        }
        let _ = is_request_processed;

        // XXX (C): xflt_filter() -- return NGX_OK here
        next_body_filter(r, input)
    }
}
