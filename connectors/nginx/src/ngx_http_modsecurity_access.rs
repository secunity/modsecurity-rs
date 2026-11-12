//! Port of `src/ngx_http_modsecurity_access.c`: the access phase handler,
//! which feeds the connection, URI, request headers and request body to
//! ModSecurity.

use core::ptr;

use nginx_sys::{
    NGX_AGAIN, NGX_DECLINED, NGX_DONE, NGX_ERROR, NGX_HTTP_INTERNAL_SERVER_ERROR, NGX_HTTP_SPECIAL_RESPONSE,
    NGX_HTTP_VERSION_9, NGX_HTTP_VERSION_10, NGX_HTTP_VERSION_11, NGX_HTTP_VERSION_20, NGX_OK,
    ngx_connection_local_sockaddr, ngx_http_core_module, ngx_http_core_run_phases, ngx_http_core_srv_conf_t,
    ngx_http_read_client_request_body, ngx_http_request_t, ngx_inet_get_port, ngx_int_t, ngx_list_part_t, ngx_str_t,
    ngx_table_elt_t,
};

use crate::ngx_http_modsecurity_common::Ctx;

/// `NGX_SOCKADDR_STRLEN` (an expression macro bindgen does not emit):
/// `sizeof("unix:") - 1 + NGX_UNIX_ADDRSTRLEN`, where `NGX_UNIX_ADDRSTRLEN`
/// is the size of `sun_path`.
const NGX_SOCKADDR_STRLEN: usize =
    5 + core::mem::size_of::<nginx_sys::sockaddr_un>() - core::mem::offset_of!(nginx_sys::sockaddr_un, sun_path);
use crate::ngx_http_modsecurity_module::{
    loc_conf, ngx_http_modsecurity_create_ctx, ngx_http_modsecurity_get_module_ctx,
    ngx_http_modsecurity_process_intervention,
};

/// `ngx_http_modsecurity_request_read`: post handler of
/// `ngx_http_read_client_request_body`; resumes the phases once the body
/// is read.
///
/// # Safety
/// Called by nginx with a valid request.
pub unsafe extern "C" fn ngx_http_modsecurity_request_read(r: *mut ngx_http_request_t) {
    // SAFETY: called by nginx with a valid request that has our context.
    unsafe {
        let ctx = ngx_http_modsecurity_get_module_ctx(r);

        // nginx >= 0.8.11
        let main = (*r).main;
        (*main).set_count((*main).count() - 1);

        if !ctx.is_null() && (*ctx).waiting_more_body {
            (*ctx).waiting_more_body = false;
            (*r).write_event_handler = Some(ngx_http_core_run_phases);
            ngx_http_core_run_phases(r);
        }
    }
}

/// The bytes of an `ngx_str_t`.
fn bytes(s: &ngx_str_t) -> Vec<u8> {
    if s.len == 0 || s.data.is_null() { Vec::new() } else { s.as_bytes().to_vec() }
}

/// Iterates an nginx list of `ngx_table_elt_t` (request/response headers).
///
/// # Safety
/// `part` must be the first part of a valid header list.
pub unsafe fn for_each_header(mut part: *const ngx_list_part_t, mut f: impl FnMut(&ngx_table_elt_t)) {
    // SAFETY: walks nelts elements of each part, following `next`.
    unsafe {
        while !part.is_null() {
            let data = (*part).elts as *const ngx_table_elt_t;
            for i in 0..(*part).nelts {
                f(&*data.add(i));
            }
            part = (*part).next;
        }
    }
}

/// Connection, URI and request header processing (done once, when the
/// context is created). Returns `Some(status)` when the handler must
/// return immediately.
unsafe fn process_request_line_and_headers(r: *mut ngx_http_request_t, ctx: &mut Ctx) -> Option<ngx_int_t> {
    // SAFETY: valid request with our context.
    unsafe {
        let connection = (*r).connection;
        // FIXME (C): We may want to use struct sockaddr instead of addr_text.
        let addr_text = (*connection).addr_text;

        // FIXME (C): Check if it is possible to hook on nginx on a earlier
        // phase. At this point we are doing an late connection process.
        // Maybe we have to hook into NGX_HTTP_FIND_CONFIG_PHASE, it seems to
        // be the erliest phase that nginx allow us to attach those kind of
        // hooks.
        let client_port = ngx_inet_get_port((*connection).sockaddr) as i32;
        let server_port = ngx_inet_get_port((*connection).local_sockaddr) as i32;
        let client_addr = String::from_utf8_lossy(&bytes(&addr_text)).into_owned();

        // first check if Nginx received a Host header and it's usable (i.e.
        // not empty); if yes, we can use that, otherwise try the server
        // config, namely the server_name directive (in the default config,
        // server_name is "_").
        let mut hostname = ngx_str_t::empty();
        if (*r).headers_in.server.len > 0 {
            hostname = (*r).headers_in.server;
        } else {
            let cscf =
                *(*r).srv_conf.add((*ptr::addr_of!(ngx_http_core_module)).ctx_index) as *mut ngx_http_core_srv_conf_t;
            if (*cscf).server_name.len > 0 {
                hostname = (*cscf).server_name;
            }
        }
        if hostname.len > 0 {
            // set the hostname in the transaction (ModSecurity >= 3.0.13)
            ctx.modsec_transaction.set_request_host_name(&String::from_utf8_lossy(hostname.as_bytes()));
        }

        let mut addr = [0u8; NGX_SOCKADDR_STRLEN];
        let mut s = ngx_str_t { len: NGX_SOCKADDR_STRLEN, data: addr.as_mut_ptr() };
        if ngx_connection_local_sockaddr((*r).connection, &mut s, 0) != NGX_OK as ngx_int_t {
            return Some(NGX_HTTP_INTERNAL_SERVER_ERROR as ngx_int_t);
        }
        let server_addr = String::from_utf8_lossy(&bytes(&s)).into_owned();

        ctx.modsec_transaction.process_connection(&client_addr, client_port, &server_addr, server_port);

        // FIXME (C): Check how we can finalize a request without crash
        // nginx. I don't think nginx is expecting to finalize a request at
        // that point as it seems that it clean the ngx_http_request_t
        // information and try to use it later.
        let ret = ngx_http_modsecurity_process_intervention(ctx, r, true);
        if ret > 0 {
            ctx.intervention_triggered = true;
            return Some(ret);
        }

        let http_version: Vec<u8> = match (*r).http_version as u32 {
            NGX_HTTP_VERSION_9 => b"0.9".to_vec(),
            NGX_HTTP_VERSION_10 => b"1.0".to_vec(),
            NGX_HTTP_VERSION_11 => b"1.1".to_vec(),
            NGX_HTTP_VERSION_20 => b"2.0".to_vec(),
            _ => {
                let p = bytes(&(*r).http_protocol);
                if p.len() > 5 && p.starts_with(b"HTTP/") { p[5..].to_vec() } else { b"1.0".to_vec() }
            }
        };

        let n_uri = bytes(&(*r).unparsed_uri);
        let n_method = bytes(&(*r).method_name);
        if n_uri.is_empty() {
            return Some(NGX_HTTP_INTERNAL_SERVER_ERROR as ngx_int_t);
        }

        ctx.modsec_transaction.process_uri(&n_uri, &n_method, &http_version);
        let ret = ngx_http_modsecurity_process_intervention(ctx, r, true);
        if ret > 0 {
            ctx.intervention_triggered = true;
            return Some(ret);
        }

        // Since incoming request headers are already in place, lets send
        // it to ModSecurity.
        for_each_header(&(*r).headers_in.headers.part, |h| {
            ctx.modsec_transaction.add_request_header(h.key.as_bytes(), &bytes(&h.value));
        });

        // Since ModSecurity already knew about all headers, i guess it is
        // safe to process this information.
        ctx.modsec_transaction.process_request_headers();
        let ret = ngx_http_modsecurity_process_intervention(ctx, r, true);
        if (*r).error_page() != 0 {
            return Some(NGX_DECLINED as ngx_int_t);
        }
        if ret > 0 {
            ctx.intervention_triggered = true;
            return Some(ret);
        }
    }
    None
}

/// `ngx_http_modsecurity_access_handler`
///
/// # Safety
/// Called by nginx (access phase) with a valid request.
pub unsafe extern "C" fn ngx_http_modsecurity_access_handler(r: *mut ngx_http_request_t) -> ngx_int_t {
    // SAFETY: called by nginx in the access phase with a valid request.
    unsafe {
        let mcf = loc_conf(r);
        if mcf.is_null() || (*mcf).enable != 1 {
            return NGX_DECLINED as ngx_int_t;
        }

        let mut ctx = ngx_http_modsecurity_get_module_ctx(r);
        if ctx.is_null() {
            ctx = ngx_http_modsecurity_create_ctx(r);
            if ctx.is_null() {
                return NGX_HTTP_INTERNAL_SERVER_ERROR as ngx_int_t;
            }
            if let Some(rc) = process_request_line_and_headers(r, &mut *ctx) {
                return rc;
            }
        }
        let ctx = &mut *ctx;

        if ctx.request_body_processed {
            // should we use r->internal or r->filter_finalize?
            return NGX_DECLINED as ngx_int_t;
        }
        if ctx.intervention_triggered {
            return NGX_DECLINED as ngx_int_t;
        }
        if ctx.waiting_more_body {
            return NGX_DONE as ngx_int_t;
        }

        if !ctx.body_requested {
            ctx.body_requested = true;
            // TODO (C): Check if there is any benefit to use
            // request_body_in_single_buf set to 1.
            (*r).set_request_body_in_single_buf(1);
            (*r).set_request_body_in_persistent_file(1);
            if (*r).request_body_in_file_only() == 0 {
                // If the above condition fails, then the flag below will
                // have been set correctly elsewhere. We need to set the flag
                // here for other conditions (client_body_in_file_only not
                // used but client_body_buffer_size is).
                (*r).set_request_body_in_clean_file(1);
            }

            let rc = ngx_http_read_client_request_body(r, Some(ngx_http_modsecurity_request_read));
            if rc == NGX_ERROR as ngx_int_t || rc >= NGX_HTTP_SPECIAL_RESPONSE as ngx_int_t {
                return rc;
            }
            if rc == NGX_AGAIN as ngx_int_t {
                ctx.waiting_more_body = true;
                return NGX_DONE as ngx_int_t;
            }
        }

        if !ctx.waiting_more_body {
            let mut already_inspected = false;
            (*r).write_event_handler = Some(ngx_http_core_run_phases);

            // TODO (C): Speed up the analysis by sending chunk while they
            // arrive. Notice that we are waiting for the full request body
            // to start to process it.
            let rb = (*r).request_body;
            let mut chain = if rb.is_null() { ptr::null_mut() } else { (*rb).bufs };

            if !rb.is_null() && !(*rb).temp_file.is_null() {
                // Request body was saved to a file, probably we don't have
                // a copy of it in memory.
                let file_name = bytes(&(*(*rb).temp_file).file.name);
                ctx.modsec_transaction.request_body_from_file(&String::from_utf8_lossy(&file_name));
                already_inspected = true;
            }

            while !chain.is_null() && !already_inspected {
                let buf = (*chain).buf;
                let data = (*buf).pos;
                let len = (*buf).last.offset_from(data) as usize;
                let slice = if len == 0 || data.is_null() { &[][..] } else { core::slice::from_raw_parts(data, len) };
                ctx.modsec_transaction.append_request_body(slice);

                if (*buf).last_buf() != 0 {
                    break;
                }
                chain = (*chain).next;

                // XXX (C): chains are processed one-by-one, maybe worth to
                // pass all chains and then call intervention() ?
                //
                // ModSecurity may perform stream inspection on this buffer,
                // it may ask for a intervention in consequence of that.
                let ret = ngx_http_modsecurity_process_intervention(ctx, r, false);
                if ret > 0 {
                    return ret;
                }
            }

            // At this point, all the request body was sent to ModSecurity
            // and we want to make sure that all the request body inspection
            // happened; consequently we have to check if ModSecurity have
            // returned any kind of intervention.
            ctx.modsec_transaction.process_request_body();
            ctx.request_body_processed = true;

            let ret = ngx_http_modsecurity_process_intervention(ctx, r, false);
            if (*r).error_page() != 0 {
                return NGX_DECLINED as ngx_int_t;
            }
            if ret > 0 {
                return ret;
            }
        }

        NGX_DECLINED as ngx_int_t
    }
}
