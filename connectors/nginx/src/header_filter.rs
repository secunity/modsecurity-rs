//! The header filter, which feeds the response status line and headers to
//! ModSecurity.

use core::ptr;

use nginx_sys::{
    NGX_HTTP_INTERNAL_SERVER_ERROR, ngx_http_output_header_filter_pt, ngx_http_request_t, ngx_http_top_header_filter,
    ngx_int_t,
};

use crate::context::Ctx;
use crate::intervention::process_intervention;
use crate::module::ngx_http_modsecurity_module;
use crate::nginx::{Request, catch_panic};

static mut NGX_HTTP_NEXT_HEADER_FILTER: ngx_http_output_header_filter_pt = None;

/// Sends one response header to ModSecurity (recording it for the sanity
/// checks when they are compiled in).
fn add_header(request: &Request<'_>, ctx: &mut Ctx, name: &[u8], value: &[u8]) {
    #[cfg(feature = "sanity-checks")]
    store_header(ctx, name, value);
    let _ = request;
    ctx.modsec_transaction.add_response_header(name, value);
}

/// Records a header sent to ModSecurity, for the sanity checks
/// (`ngx_http_modsecurity_store_ctx_header`).
#[cfg(feature = "sanity-checks")]
pub fn store_header(ctx: &mut Ctx, name: &[u8], value: &[u8]) {
    ctx.sanity_headers_out.push(crate::context::Header { name: name.to_vec(), value: value.to_vec() });
}

/// Sends the headers nginx keeps outside of the list of response headers
/// (`ngx_http_modsecurity_headers_out`), in the order of the C module.
fn add_headers_nginx_generates(request: &Request<'_>, ctx: &mut Ctx) {
    add_header(request, ctx, b"Server", &request.server_header());
    add_header(request, ctx, b"Date", &request.date_header());
    if let Some(length) = request.content_length() {
        add_header(request, ctx, b"Content-Length", length.to_string().as_bytes());
    }
    if let Some(content_type) = request.content_type() {
        add_header(request, ctx, b"Content-Type", &content_type);
    }
    if let Some(last_modified) = request.last_modified_header() {
        add_header(request, ctx, b"Last-Modified", &last_modified);
    }

    let connection: &[u8] = if request.is_upgrade() {
        b"upgrade"
    } else if request.keepalive() {
        if let Some(timeout) = request.keepalive_header_timeout() {
            add_header(request, ctx, b"Keep-Alive", format!("timeout={}", timeout).as_bytes());
        }
        b"keep-alive"
    } else {
        b"close"
    };
    add_header(request, ctx, b"Connection", connection);

    if request.chunked() {
        add_header(request, ctx, b"Transfer-Encoding", b"chunked");
    }
    if request.gzip_vary() {
        add_header(request, ctx, b"Vary", b"Accept-Encoding");
    }
}

/// Puts this module's header filter at the top of nginx's chain.
///
/// # Safety
/// Called once from postconfiguration.
pub unsafe fn ngx_http_modsecurity_header_filter_init() -> ngx_int_t {
    // SAFETY: nginx configures filters single-threaded.
    unsafe {
        NGX_HTTP_NEXT_HEADER_FILTER = ngx_http_top_header_filter;
        ngx_http_top_header_filter = Some(ngx_http_modsecurity_header_filter);
    }
    nginx_sys::NGX_OK as ngx_int_t
}

fn next_header_filter(request: &Request<'_>) -> ngx_int_t {
    // SAFETY: the next filter was saved at init, and is given the request
    // this filter was called with.
    unsafe {
        match NGX_HTTP_NEXT_HEADER_FILTER {
            Some(f) => f(request.as_ptr()),
            None => nginx_sys::NGX_OK as ngx_int_t,
        }
    }
}

/// Gives the response headers and status to ModSecurity and runs its
/// response headers phase. `Some(status)`: the request ends with it.
fn inspect_headers(request: &Request<'_>, ctx: &mut Ctx) -> Option<ngx_int_t> {
    // TODO: this could be skipped when `SecResponseBodyAccess` is off; the
    // C module asks for it in every case.
    request.keep_response_in_memory();
    ctx.processed = true;

    // Not every header is in the list of response headers: nginx keeps some
    // as fields of `headers_out`, and `ngx_http_header_filter`, which writes
    // the response head straight to the write filter, generates others.
    // Those are worked out as nginx will send them; then the list is read,
    // which other modules in the chain may have added to.
    add_headers_nginx_generates(request, ctx);
    request.for_each_header_out(|name, value| add_header(request, ctx, name, value));

    // nginx answers with HTTP/1.1, unless the request came over HTTP/2.
    let version = if request.is_http2() { "HTTP 2.0" } else { "HTTP 1.1" };

    ctx.modsec_transaction.process_response_headers(u16::try_from(request.response_status()).unwrap_or(0), version);
    let ret = process_intervention(ctx, request, false);
    if request.error_page() {
        return None;
    }
    (ret > 0).then_some(ret)
}

/// The header filter.
///
/// # Safety
/// Called by nginx with a valid request.
pub unsafe extern "C" fn ngx_http_modsecurity_header_filter(r: *mut ngx_http_request_t) -> ngx_int_t {
    // SAFETY: nginx calls the filter with a valid request.
    let Some(request) = (unsafe { Request::new(r) }) else {
        return nginx_sys::NGX_ERROR as ngx_int_t;
    };
    catch_panic(
        request.log(),
        "the header filter",
        // SAFETY: this filter belongs to this module.
        || unsafe {
            request.finalize_from_filter(
                ptr::addr_of_mut!(ngx_http_modsecurity_module),
                NGX_HTTP_INTERNAL_SERVER_ERROR as ngx_int_t,
            )
        },
        || header_filter(&request),
    )
}

fn header_filter(request: &Request<'_>) -> ngx_int_t {
    // The response of a subrequest is not the response to the client: it
    // passes untouched.
    if request.is_subrequest() {
        return next_header_filter(request);
    }
    // SAFETY: the context lives until the request pool is destroyed, and
    // nothing else uses it while this filter inspects the headers.
    let ctx = unsafe { Ctx::find(request).as_mut() };
    let ctx = match ctx {
        Some(ctx) if !ctx.intervention_triggered && !ctx.processed => ctx,
        _ => return next_header_filter(request),
    };

    if let Some(status) = inspect_headers(request, ctx) {
        // SAFETY: this filter belongs to this module.
        return unsafe { request.finalize_from_filter(ptr::addr_of_mut!(ngx_http_modsecurity_module), status) };
    }

    // The content length is left as it is, so the response body cannot be
    // changed in size. (The C module has the line that would unset it,
    // `r->headers_out.content_length_n = -1;`, commented out for its spdy
    // test.)
    next_header_filter(request)
}
