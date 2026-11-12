//! Port of `src/ngx_http_modsecurity_header_filter.c`: feeds the response
//! status line and headers to ModSecurity.

use core::ptr;

use nginx_sys::{
    NGINX_VER, NGX_HTTP_SWITCHING_PROTOCOLS, ngx_cached_http_time, ngx_http_core_loc_conf_t, ngx_http_core_module,
    ngx_http_filter_finalize_request, ngx_http_output_header_filter_pt, ngx_http_request_t, ngx_http_time,
    ngx_http_top_header_filter, ngx_int_t, ngx_str_t,
};

use crate::ngx_http_modsecurity_access::for_each_header;
use crate::ngx_http_modsecurity_common::Ctx;
use crate::ngx_http_modsecurity_module::{
    ngx_http_modsecurity_get_module_ctx, ngx_http_modsecurity_module, ngx_http_modsecurity_process_intervention,
};

static mut NGX_HTTP_NEXT_HEADER_FILTER: ngx_http_output_header_filter_pt = None;

/// `ngx_http_modsecurity_resolv_header_pt`: adds one header that nginx keeps
/// outside of `headers_out.headers`. Returns the
/// `msc_add_n_response_header` result (or 1 when nothing was added).
type Resolver = unsafe fn(r: *mut ngx_http_request_t, ctx: &mut Ctx, name: &[u8]) -> ngx_int_t;

/// `ngx_http_modsecurity_headers_out`
const NGX_HTTP_MODSECURITY_HEADERS_OUT: [(&[u8], Resolver); 8] = [
    (b"Server", resolv_header_server),
    (b"Date", resolv_header_date),
    (b"Content-Length", resolv_header_content_length),
    (b"Content-Type", resolv_header_content_type),
    (b"Last-Modified", resolv_header_last_modified),
    (b"Connection", resolv_header_connection),
    (b"Transfer-Encoding", resolv_header_transfer_encoding),
    (b"Vary", resolv_header_vary),
];

/// `ngx_http_get_module_loc_conf(r, ngx_http_core_module)`
unsafe fn core_loc_conf(r: *mut ngx_http_request_t) -> *mut ngx_http_core_loc_conf_t {
    // SAFETY: valid request.
    unsafe { *(*r).loc_conf.add((*ptr::addr_of!(ngx_http_core_module)).ctx_index) as *mut ngx_http_core_loc_conf_t }
}

/// Sends one response header to ModSecurity (recording it for the sanity
/// checks when enabled).
unsafe fn add_header(r: *mut ngx_http_request_t, ctx: &mut Ctx, name: &[u8], value: &[u8]) -> ngx_int_t {
    #[cfg(feature = "sanity-checks")]
    // SAFETY: valid request.
    unsafe {
        store_header(ctx, r, name, value)
    };
    let _ = r;
    ctx.modsec_transaction.add_response_header(name, value);
    // `msc_add_n_response_header` always succeeds.
    1
}

/// `ngx_http_modsecurity_store_ctx_header` (sanity checks).
///
/// # Safety
/// `r` must be the request of `ctx`.
#[cfg(feature = "sanity-checks")]
pub unsafe fn ngx_http_modsecurity_store_ctx_header(
    ctx: &mut Ctx,
    r: *mut ngx_http_request_t,
    name: &ngx_str_t,
    value: &ngx_str_t,
) -> ngx_int_t {
    // SAFETY: per the contract.
    unsafe { store_header(ctx, r, name.as_bytes(), value.as_bytes()) }
}

#[cfg(feature = "sanity-checks")]
unsafe fn store_header(ctx: &mut Ctx, r: *mut ngx_http_request_t, name: &[u8], value: &[u8]) -> ngx_int_t {
    // SAFETY: valid request.
    let mcf = unsafe { crate::ngx_http_modsecurity_module::loc_conf(r) };
    // SAFETY: checked for null.
    if mcf.is_null() || unsafe { (*mcf).sanity_checks_enabled } == nginx_sys::NGX_CONF_UNSET as nginx_sys::ngx_flag_t {
        return nginx_sys::NGX_OK as ngx_int_t;
    }
    ctx.sanity_headers_out
        .push(crate::ngx_http_modsecurity_common::Header { name: name.to_vec(), value: value.to_vec() });
    nginx_sys::NGX_OK as ngx_int_t
}

unsafe fn resolv_header_server(r: *mut ngx_http_request_t, ctx: &mut Ctx, name: &[u8]) -> ngx_int_t {
    // SAFETY: valid request.
    unsafe {
        let clcf = core_loc_conf(r);
        let value: Vec<u8> = if (*r).headers_out.server.is_null() {
            // The C code uses sizeof() of the string literals, so the value
            // includes the terminating NUL byte.
            if (*clcf).server_tokens != 0 { NGINX_VER.to_bytes_with_nul().to_vec() } else { b"nginx\0".to_vec() }
        } else {
            (*(*r).headers_out.server).value.as_bytes().to_vec()
        };
        add_header(r, ctx, name, &value)
    }
}

unsafe fn resolv_header_date(r: *mut ngx_http_request_t, ctx: &mut Ctx, name: &[u8]) -> ngx_int_t {
    // SAFETY: valid request; ngx_cached_http_time is maintained by nginx.
    unsafe {
        let date: Vec<u8> = if (*r).headers_out.date.is_null() {
            let t: ngx_str_t = ptr::read_volatile(ptr::addr_of!(ngx_cached_http_time));
            t.as_bytes().to_vec()
        } else {
            (*(*r).headers_out.date).value.as_bytes().to_vec()
        };
        add_header(r, ctx, name, &date)
    }
}

unsafe fn resolv_header_content_length(r: *mut ngx_http_request_t, ctx: &mut Ctx, name: &[u8]) -> ngx_int_t {
    // SAFETY: valid request.
    unsafe {
        if (*r).headers_out.content_length_n > 0 {
            let value = (*r).headers_out.content_length_n.to_string();
            return add_header(r, ctx, name, value.as_bytes());
        }
    }
    1
}

unsafe fn resolv_header_content_type(r: *mut ngx_http_request_t, ctx: &mut Ctx, name: &[u8]) -> ngx_int_t {
    // SAFETY: valid request.
    unsafe {
        if (*r).headers_out.content_type.len > 0 {
            let value = (*r).headers_out.content_type.as_bytes().to_vec();
            return add_header(r, ctx, name, &value);
        }
    }
    1
}

unsafe fn resolv_header_last_modified(r: *mut ngx_http_request_t, ctx: &mut Ctx, name: &[u8]) -> ngx_int_t {
    // SAFETY: valid request; ngx_http_time writes at most 29 bytes.
    unsafe {
        if (*r).headers_out.last_modified_time == -1 {
            return 1;
        }
        let mut buf = [0u8; 1024];
        let p = ngx_http_time(buf.as_mut_ptr(), (*r).headers_out.last_modified_time);
        let len = p.offset_from(buf.as_ptr()) as usize;
        add_header(r, ctx, name, &buf[..len])
    }
}

unsafe fn resolv_header_connection(r: *mut ngx_http_request_t, ctx: &mut Ctx, name: &[u8]) -> ngx_int_t {
    // SAFETY: valid request.
    unsafe {
        let clcf = core_loc_conf(r);
        let connection: &[u8] = if (*r).headers_out.status == NGX_HTTP_SWITCHING_PROTOCOLS as usize {
            b"upgrade"
        } else if (*r).keepalive() != 0 {
            if (*clcf).keepalive_header != 0 {
                let value = format!("timeout={}", (*clcf).keepalive_header);
                add_header(r, ctx, b"Keep-Alive", value.as_bytes());
            }
            b"keep-alive"
        } else {
            b"close"
        };
        add_header(r, ctx, name, connection)
    }
}

unsafe fn resolv_header_transfer_encoding(r: *mut ngx_http_request_t, ctx: &mut Ctx, name: &[u8]) -> ngx_int_t {
    // SAFETY: valid request.
    unsafe {
        if (*r).chunked() != 0 {
            return add_header(r, ctx, name, b"chunked");
        }
    }
    1
}

unsafe fn resolv_header_vary(r: *mut ngx_http_request_t, ctx: &mut Ctx, name: &[u8]) -> ngx_int_t {
    #[cfg(ngx_feature = "http_gzip")]
    // SAFETY: valid request.
    unsafe {
        let clcf = core_loc_conf(r);
        if (*r).gzip_vary() != 0 && (*clcf).gzip_vary != 0 {
            return add_header(r, ctx, name, b"Accept-Encoding");
        }
    }
    let _ = (r, ctx, name);
    1
}

/// `ngx_http_modsecurity_header_filter_init`
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

unsafe fn next_header_filter(r: *mut ngx_http_request_t) -> ngx_int_t {
    // SAFETY: the next filter was saved at init.
    unsafe {
        match NGX_HTTP_NEXT_HEADER_FILTER {
            Some(f) => f(r),
            None => nginx_sys::NGX_OK as ngx_int_t,
        }
    }
}

/// `ngx_http_modsecurity_header_filter`
///
/// # Safety
/// Called by nginx with a valid request.
pub unsafe extern "C" fn ngx_http_modsecurity_header_filter(r: *mut ngx_http_request_t) -> ngx_int_t {
    // SAFETY: called by nginx with a valid request.
    unsafe {
        // XXX (C): if NOT_MODIFIED, do we need to process it at all? see
        // xslt_header_filter()
        let ctx = ngx_http_modsecurity_get_module_ctx(r);
        if ctx.is_null() {
            return next_header_filter(r);
        }
        let ctx = &mut *ctx;
        if ctx.intervention_triggered {
            return next_header_filter(r);
        }
        // XXX (C): can it happen ? already processed i mean
        if ctx.processed {
            // FIXME (C): verify if this request is already processed.
            return next_header_filter(r);
        }

        // Lets ask nginx to keep the response body in memory.
        //
        // FIXME (C): I don't see a reason to keep it `1' when
        // SecResponseBody is disabled.
        (*r).set_filter_need_in_memory(1);
        ctx.processed = true;

        // Assuming ModSecurity module is running immediately before the
        // ngx_http_header_filter, we will be able to populate ModSecurity
        // with headers from the headers_out structure. As
        // ngx_http_header_filter place a direct call to the
        // ngx_http_write_filter_module, we cannot hook between those two. In
        // order to enumerate all headers, we first look at the headers_out
        // structure, and later we look into the ngx_list_part_t. The
        // ngx_list_part_t must be checked. Other module(s) in the chain may
        // added some content to it.
        for (name, resolver) in NGX_HTTP_MODSECURITY_HEADERS_OUT.iter() {
            resolver(r, ctx, name);
        }

        for_each_header(&(*r).headers_out.headers.part, |h| {
            add_header(r, ctx, h.key.as_bytes(), h.value.as_bytes());
        });

        // prepare extra paramters for msc_process_response_headers()
        let status = if (*r).err_status != 0 { (*r).err_status } else { (*r).headers_out.status };

        // NGINX always sends HTTP response with HTTP/1.1, except cases when
        // HTTP V2 module is enabled, and request has been posted with
        // HTTP/2.0.
        #[allow(unused_mut)]
        let mut http_response_ver = "HTTP 1.1";
        #[cfg(ngx_feature = "http_v2")]
        if !(*r).stream.is_null() {
            http_response_ver = "HTTP 2.0";
        }

        ctx.modsec_transaction.process_response_headers(status as i32, http_response_ver);
        let ret = ngx_http_modsecurity_process_intervention(ctx, r, false);
        if (*r).error_page() != 0 {
            return next_header_filter(r);
        }
        if ret > 0 {
            return ngx_http_filter_finalize_request(r, ptr::addr_of_mut!(ngx_http_modsecurity_module), ret);
        }

        // Proxies will not like this... but it is necessary to unset the
        // content length in order to manipulate the content of response body
        // in ModSecurity. (The C code keeps this commented out to make the
        // spdy test work: `r->headers_out.content_length_n = -1;`)
        next_header_filter(r)
    }
}
