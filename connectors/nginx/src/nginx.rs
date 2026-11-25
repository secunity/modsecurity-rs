//! nginx as the handlers see it: [`Request`], the request a handler was
//! called for, and the buffers of a chain.
//!
//! Everything the handlers read from or write to nginx's structures goes
//! through here, so that the handlers themselves are safe code. A
//! [`Request`] is made from the pointer nginx hands to a handler
//! ([`Request::new`], the one `unsafe` step of a handler) and is valid
//! while that handler runs.
//!
//! The methods take `&self` although some change the request: nginx
//! changes it under us anyway (reading the body can run other handlers of
//! this module for the same request), so no Rust reference to the nginx
//! structure is kept, only its address.

use core::ffi::c_void;
use core::marker::PhantomData;
use core::ptr::{self, NonNull};

use nginx_sys::{
    NGINX_VER, NGX_HTTP_SWITCHING_PROTOCOLS, NGX_HTTP_VERSION_9, NGX_HTTP_VERSION_10, NGX_HTTP_VERSION_11,
    NGX_HTTP_VERSION_20, NGX_OK, ngx_cached_http_time, ngx_chain_t, ngx_connection_local_sockaddr,
    ngx_http_client_body_handler_pt, ngx_http_complex_value, ngx_http_complex_value_t, ngx_http_core_loc_conf_t,
    ngx_http_core_module, ngx_http_core_run_phases, ngx_http_core_srv_conf_t, ngx_http_filter_finalize_request,
    ngx_http_read_client_request_body, ngx_http_request_t, ngx_http_time, ngx_inet_get_port, ngx_int_t,
    ngx_list_part_t, ngx_list_push, ngx_log_error_core, ngx_log_t, ngx_module_t, ngx_pnalloc, ngx_pool_cleanup_add,
    ngx_str_t, ngx_table_elt_t, ngx_uint_t,
};

/// `NGX_SOCKADDR_STRLEN` (an expression macro bindgen does not emit):
/// `sizeof("unix:") - 1 + NGX_UNIX_ADDRSTRLEN`, where `NGX_UNIX_ADDRSTRLEN`
/// is the size of `sun_path`.
const NGX_SOCKADDR_STRLEN: usize =
    5 + core::mem::size_of::<nginx_sys::sockaddr_un>() - core::mem::offset_of!(nginx_sys::sockaddr_un, sun_path);

/// `s` up to its first NUL byte: what nginx is given of it as a C string.
pub fn c_str(s: &[u8]) -> &[u8] {
    match s.iter().position(|&c| c == 0) {
        Some(end) => &s[..end],
        None => s,
    }
}

/// The bytes of an `ngx_str_t` (empty for a null one).
fn bytes(s: &ngx_str_t) -> Vec<u8> {
    if s.len == 0 || s.data.is_null() { Vec::new() } else { s.as_bytes().to_vec() }
}

/// An nginx log (`r->connection->log`), or none.
#[derive(Clone, Copy)]
pub struct Log(*mut ngx_log_t);

// SAFETY: the pointer is only dereferenced on the worker thread that owns
// the request (the engine calls the log callback synchronously from the
// transaction methods the connector invokes); `Send` is only needed because
// the transaction's callback data must be `Send`.
unsafe impl Send for Log {}

impl Log {
    /// The log `log` points to.
    ///
    /// # Safety
    /// `log` must be null, or valid for as long as this value is used.
    pub unsafe fn new(log: *mut ngx_log_t) -> Self {
        Log(log)
    }

    /// `ngx_log_error(level, log, 0, "%s", msg)`: logs a byte string
    /// (truncated at the first NUL, like the C string it replaces).
    pub fn error(self, level: ngx_uint_t, msg: &[u8]) {
        // SAFETY: a valid log, by the contract of `new`.
        if self.0.is_null() || level > unsafe { (*self.0).log_level } {
            return;
        }
        let mut c = c_str(msg).to_vec();
        c.push(0);
        // SAFETY: "%s" with one NUL terminated string argument.
        unsafe { ngx_log_error_core(level, self.0, 0, c"%s".as_ptr(), c.as_ptr() as *const c_void) };
    }
}

/// Runs `f`, the body of a function nginx calls. A panic in `f` does not
/// unwind into nginx (which aborts the worker process): it is logged on
/// `log`, naming `handler`, and `on_panic` gives the result instead.
pub fn catch_panic<T>(log: Log, handler: &str, on_panic: impl FnOnce() -> T, f: impl FnOnce() -> T) -> T {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(v) => v,
        Err(payload) => {
            let message = payload
                .downcast_ref::<&str>()
                .copied()
                .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
                .unwrap_or("no message");
            log.error(
                nginx_sys::NGX_LOG_ERR as ngx_uint_t,
                format!("ModSecurity: internal error in {handler}: {message}").as_bytes(),
            );
            on_panic()
        }
    }
}

/// The log of the running cycle (`ngx_cycle->log`), for code that has no
/// request or configuration at hand.
pub fn cycle_log() -> Log {
    // SAFETY: nginx sets ngx_cycle before it loads modules, and the log of a
    // cycle lives as long as the cycle.
    unsafe {
        let cycle = ptr::read_volatile(ptr::addr_of!(nginx_sys::ngx_cycle));
        Log::new(if cycle.is_null() { ptr::null_mut() } else { (*cycle).log })
    }
}

/// A buffer of a chain: its data, and whether it is the last of the body.
pub struct Buffer<'c> {
    pub data: &'c [u8],
    pub last: bool,
}

/// The buffers of an nginx chain, in order.
pub struct Buffers<'c> {
    chain: *mut ngx_chain_t,
    _chain: PhantomData<&'c ngx_chain_t>,
}

impl<'c> Buffers<'c> {
    /// The buffers of `chain` (none for a null chain).
    ///
    /// # Safety
    /// `chain` must be null or a valid chain, whose buffers stay as they
    /// are for `'c`.
    pub unsafe fn new(chain: *mut ngx_chain_t) -> Self {
        Buffers { chain, _chain: PhantomData }
    }
}

impl<'c> Iterator for Buffers<'c> {
    type Item = Buffer<'c>;

    fn next(&mut self) -> Option<Buffer<'c>> {
        if self.chain.is_null() {
            return None;
        }
        // SAFETY: a valid chain link and buffer, by the contract of `new`;
        // `pos..last` is the data of the buffer.
        unsafe {
            let buf = (*self.chain).buf;
            let data = (*buf).pos;
            let len = (*buf).last.offset_from(data) as usize;
            let data = if len == 0 || data.is_null() { &[][..] } else { core::slice::from_raw_parts(data, len) };
            self.chain = (*self.chain).next;
            Some(Buffer { data, last: (*buf).last_buf() != 0 })
        }
    }
}

/// Calls `f` with the name and value of each header of a list.
///
/// # Safety
/// `part` must be the first part of a valid list of `ngx_table_elt_t`.
unsafe fn for_each_header(mut part: *const ngx_list_part_t, mut f: impl FnMut(&[u8], &ngx_str_t)) {
    // SAFETY: walks nelts elements of each part, following `next`.
    unsafe {
        while !part.is_null() {
            let data = (*part).elts as *const ngx_table_elt_t;
            for i in 0..(*part).nelts {
                let h = &*data.add(i);
                f(h.key.as_bytes(), &h.value);
            }
            part = (*part).next;
        }
    }
}

/// The request a handler of this module was called for.
pub struct Request<'r> {
    r: NonNull<ngx_http_request_t>,
    _request: PhantomData<&'r ngx_http_request_t>,
}

impl<'r> Request<'r> {
    /// The request `r` points to; `None` for a null pointer.
    ///
    /// # Safety
    /// `r` must be the request nginx called a handler of an HTTP module
    /// with, and `'r` must end before that handler returns.
    pub unsafe fn new(r: *mut ngx_http_request_t) -> Option<Self> {
        Some(Request { r: NonNull::new(r)?, _request: PhantomData })
    }

    /// The request, for nginx.
    pub fn as_ptr(&self) -> *mut ngx_http_request_t {
        self.r.as_ptr()
    }

    // --- Module data -----------------------------------------------------

    /// `ngx_http_get_module_loc_conf(r, module)` as a `T`.
    ///
    /// # Safety
    /// `module` must be an HTTP module whose location configuration is a
    /// `T` (or null).
    pub unsafe fn loc_conf<T>(&self, module: *const ngx_module_t) -> Option<&'r T> {
        // SAFETY: loc_conf has an entry for every HTTP module's ctx_index,
        // and configurations outlive the requests served with them.
        unsafe { (*(*self.as_ptr()).loc_conf.add((*module).ctx_index) as *const T).as_ref() }
    }

    /// `ngx_http_get_module_main_conf(r, module)` as a `T`.
    ///
    /// # Safety
    /// `module` must be an HTTP module whose main configuration is a `T`
    /// (or null).
    pub unsafe fn main_conf<T>(&self, module: *const ngx_module_t) -> Option<&'r T> {
        // SAFETY: as for `loc_conf`.
        unsafe { (*(*self.as_ptr()).main_conf.add((*module).ctx_index) as *const T).as_ref() }
    }

    /// `ngx_http_get_module_ctx(r, module)`.
    ///
    /// # Safety
    /// `module` must be an HTTP module.
    pub unsafe fn module_ctx(&self, module: *const ngx_module_t) -> *mut c_void {
        // SAFETY: ctx has an entry for every HTTP module's ctx_index.
        unsafe { *(*self.as_ptr()).ctx.add((*module).ctx_index) }
    }

    /// `ngx_http_set_ctx(r, ctx, module)`.
    ///
    /// # Safety
    /// `module` must be an HTTP module.
    pub unsafe fn set_module_ctx(&self, module: *const ngx_module_t, ctx: *mut c_void) {
        // SAFETY: as for `module_ctx`.
        unsafe { *(*self.as_ptr()).ctx.add((*module).ctx_index) = ctx };
    }

    /// Has `handler` called with `data` when the request's pool is
    /// destroyed; `false` when nginx is out of memory.
    pub fn add_cleanup(&self, handler: unsafe extern "C" fn(*mut c_void), data: *mut c_void) -> bool {
        // SAFETY: a valid request has a pool; the new cleanup is filled in
        // before nginx can run it.
        unsafe {
            let cln = ngx_pool_cleanup_add((*self.as_ptr()).pool, 0);
            if cln.is_null() {
                return false;
            }
            (*cln).handler = Some(handler);
            (*cln).data = data;
            true
        }
    }

    /// The data of the first cleanup of the request's pool whose handler
    /// is `handler`.
    pub fn cleanup_data(&self, handler: unsafe extern "C" fn(*mut c_void)) -> Option<*mut c_void> {
        // SAFETY: walks the cleanups of the request's pool.
        unsafe {
            let mut cln = (*(*self.as_ptr()).pool).cleanup;
            while !cln.is_null() {
                if (*cln).handler.is_some_and(|h| core::ptr::fn_addr_eq(h, handler)) {
                    return Some((*cln).data);
                }
                cln = (*cln).next;
            }
            None
        }
    }

    /// The value of a complex value (a string with variables) for this
    /// request; `None` when nginx fails to evaluate it.
    ///
    /// # Safety
    /// `value` must be a compiled complex value.
    pub unsafe fn complex_value(&self, value: *mut ngx_http_complex_value_t) -> Option<Vec<u8>> {
        let mut s = ngx_str_t::empty();
        // SAFETY: a valid request and complex value.
        if unsafe { ngx_http_complex_value(self.as_ptr(), value, &mut s) } != NGX_OK as ngx_int_t {
            return None;
        }
        Some(s.as_bytes().to_vec())
    }

    // --- The connection --------------------------------------------------

    /// The log of the connection.
    pub fn log(&self) -> Log {
        // SAFETY: a request has a connection, whose log outlives it.
        unsafe { Log::new((*(*self.as_ptr()).connection).log) }
    }

    /// The address of the client, as text.
    pub fn client_addr(&self) -> Vec<u8> {
        // SAFETY: a request has a connection.
        unsafe { bytes(&(*(*self.as_ptr()).connection).addr_text) }
    }

    pub fn client_port(&self) -> u16 {
        // SAFETY: a request has a connection with a socket address.
        unsafe { ngx_inet_get_port((*(*self.as_ptr()).connection).sockaddr) }
    }

    pub fn server_port(&self) -> u16 {
        // SAFETY: a request has a connection with a local socket address.
        unsafe { ngx_inet_get_port((*(*self.as_ptr()).connection).local_sockaddr) }
    }

    /// The local address of the connection, as text; `None` when nginx
    /// cannot tell.
    pub fn server_addr(&self) -> Option<Vec<u8>> {
        let mut addr = [0u8; NGX_SOCKADDR_STRLEN];
        let mut s = ngx_str_t { len: NGX_SOCKADDR_STRLEN, data: addr.as_mut_ptr() };
        // SAFETY: `s` has room for any socket address as text.
        if unsafe { ngx_connection_local_sockaddr((*self.as_ptr()).connection, &mut s, 0) } != NGX_OK as ngx_int_t {
            return None;
        }
        Some(bytes(&s))
    }

    // --- The request -----------------------------------------------------

    /// The host of the request: its `Host` header when nginx found a usable
    /// one, or else the `server_name` of the server (`_` in the default
    /// configuration); `None` when both are empty.
    pub fn host_name(&self) -> Option<Vec<u8>> {
        // SAFETY: srv_conf has an entry for the core module.
        unsafe {
            let r = self.as_ptr();
            if (*r).headers_in.server.len > 0 {
                return Some((*r).headers_in.server.as_bytes().to_vec());
            }
            let cscf =
                *(*r).srv_conf.add((*ptr::addr_of!(ngx_http_core_module)).ctx_index) as *mut ngx_http_core_srv_conf_t;
            ((*cscf).server_name.len > 0).then(|| (*cscf).server_name.as_bytes().to_vec())
        }
    }

    /// The HTTP version as ModSecurity takes it (`1.1`).
    pub fn http_version(&self) -> Vec<u8> {
        // SAFETY: reads of a valid request.
        unsafe {
            let r = self.as_ptr();
            match (*r).http_version as u32 {
                NGX_HTTP_VERSION_9 => b"0.9".to_vec(),
                NGX_HTTP_VERSION_10 => b"1.0".to_vec(),
                NGX_HTTP_VERSION_11 => b"1.1".to_vec(),
                NGX_HTTP_VERSION_20 => b"2.0".to_vec(),
                _ => {
                    let p = bytes(&(*r).http_protocol);
                    if p.len() > 5 && p.starts_with(b"HTTP/") { p[5..].to_vec() } else { b"1.0".to_vec() }
                }
            }
        }
    }

    /// The request target as the client sent it.
    pub fn unparsed_uri(&self) -> Vec<u8> {
        // SAFETY: a read of a valid request.
        unsafe { bytes(&(*self.as_ptr()).unparsed_uri) }
    }

    pub fn method_name(&self) -> Vec<u8> {
        // SAFETY: a read of a valid request.
        unsafe { bytes(&(*self.as_ptr()).method_name) }
    }

    /// Calls `f` with the name and value of each request header.
    pub fn for_each_header_in(&self, mut f: impl FnMut(&[u8], &[u8])) {
        // SAFETY: the request's list of headers.
        unsafe { for_each_header(&(*self.as_ptr()).headers_in.headers.part, |name, value| f(name, &bytes(value))) };
    }

    /// Whether the request is a subrequest (of `auth_request`, SSI,
    /// `add_before_body`, ...) rather than the request of the client.
    pub fn is_subrequest(&self) -> bool {
        // SAFETY: a read of a valid request.
        unsafe { (*self.as_ptr()).main != self.as_ptr() }
    }

    /// Whether nginx is serving an `error_page` for the request.
    pub fn error_page(&self) -> bool {
        // SAFETY: a read of a valid request.
        unsafe { (*self.as_ptr()).error_page() != 0 }
    }

    // --- The request body ------------------------------------------------

    /// Asks nginx for the whole request body, and has `handler` called once
    /// it is read: `ngx_http_read_client_request_body`, whose result this
    /// is. A body that does not fit in memory goes to a file that keeps its
    /// name until the request ends, so that ModSecurity can read it.
    pub fn read_body(&self, handler: ngx_http_client_body_handler_pt) -> ngx_int_t {
        // SAFETY: a valid request, in a phase where its body can be read.
        unsafe {
            let r = self.as_ptr();
            (*r).set_request_body_in_single_buf(1);
            (*r).set_request_body_in_persistent_file(1);
            if (*r).request_body_in_file_only() == 0 {
                // With `client_body_in_file_only`, nginx has already set
                // whether the file is removed. Otherwise the body goes to a
                // file only when it exceeds `client_body_buffer_size`, and
                // that file is removed when the request ends.
                (*r).set_request_body_in_clean_file(1);
            }
            ngx_http_read_client_request_body(r, handler)
        }
    }

    /// Releases the reference `ngx_http_read_client_request_body` took on
    /// the main request (nginx >= 0.8.11).
    pub fn release_body_reference(&self) {
        // SAFETY: a request has a main request.
        unsafe {
            let main = (*self.as_ptr()).main;
            (*main).set_count((*main).count() - 1);
        }
    }

    /// Has nginx run the phases of the request when it can write to the
    /// client again.
    pub fn run_phases_on_write(&self) {
        // SAFETY: a write of a valid request.
        unsafe { (*self.as_ptr()).write_event_handler = Some(ngx_http_core_run_phases) };
    }

    /// Runs the phases of the request from where they stopped.
    pub fn run_phases(&self) {
        // SAFETY: a valid request.
        unsafe { ngx_http_core_run_phases(self.as_ptr()) };
    }

    /// The name of the file nginx saved the request body to, when it did.
    pub fn body_file(&self) -> Option<Vec<u8>> {
        // SAFETY: reads of a valid request body.
        unsafe {
            let rb = (*self.as_ptr()).request_body;
            if rb.is_null() || (*rb).temp_file.is_null() {
                return None;
            }
            Some(bytes(&(*(*rb).temp_file).file.name))
        }
    }

    /// The request body nginx holds in memory.
    pub fn body_buffers(&self) -> Buffers<'_> {
        // SAFETY: the chain of a read request body, which nginx keeps for
        // the request.
        unsafe {
            let rb = (*self.as_ptr()).request_body;
            Buffers::new(if rb.is_null() { ptr::null_mut() } else { (*rb).bufs })
        }
    }

    // --- The response ----------------------------------------------------

    /// Whether the response header was sent.
    pub fn header_sent(&self) -> bool {
        // SAFETY: a read of a valid request.
        unsafe { (*self.as_ptr()).header_sent() != 0 }
    }

    /// Makes `url` the `Location` header of the response, replacing the
    /// one it has, and gives the header as nginx keeps it; `None` when
    /// nginx is out of memory.
    pub fn set_location(&self, url: &[u8]) -> Option<(&[u8], &[u8])> {
        // SAFETY: a valid request; the header is allocated from its pool,
        // which outlives `self`.
        unsafe {
            let r = self.as_ptr();
            // As `ngx_http_send_error_page` (`ngx_http_special_response.c`)
            // does: `ngx_http_clear_location(r)`, then a new header whose
            // `hash` is 1 (see `ngx_http_core_module.c`).
            if !(*r).headers_out.location.is_null() {
                (*(*r).headers_out.location).hash = 0;
                (*r).headers_out.location = ptr::null_mut();
            }

            let data = ngx_pnalloc((*r).pool, url.len()) as *mut u8;
            let location = ngx_list_push(&mut (*r).headers_out.headers) as *mut ngx_table_elt_t;
            if data.is_null() || location.is_null() {
                return None;
            }
            ptr::copy_nonoverlapping(url.as_ptr(), data, url.len());
            ptr::write_bytes(location, 0, 1);
            (*location).key = ngx_str_t { len: 8, data: c"Location".as_ptr() as *mut u8 };
            (*location).value = ngx_str_t { len: url.len(), data };
            (*r).headers_out.location = location;
            (*(*r).headers_out.location).hash = 1;
            Some(((*location).key.as_bytes(), (*location).value.as_bytes()))
        }
    }

    /// Asks nginx to keep the response body in memory for the body filter.
    pub fn keep_response_in_memory(&self) {
        // SAFETY: a write of a valid request.
        unsafe { (*self.as_ptr()).set_filter_need_in_memory(1) };
    }

    /// The status of the response: of the error nginx is answering with,
    /// or else of the response.
    pub fn response_status(&self) -> ngx_uint_t {
        // SAFETY: reads of a valid request.
        unsafe {
            let r = self.as_ptr();
            if (*r).err_status != 0 { (*r).err_status } else { (*r).headers_out.status }
        }
    }

    /// Whether the response goes out over HTTP/2.
    pub fn is_http2(&self) -> bool {
        #[cfg(ngx_feature = "http_v2")]
        {
            // SAFETY: a read of a valid request.
            unsafe { !(*self.as_ptr()).stream.is_null() }
        }
        #[cfg(not(ngx_feature = "http_v2"))]
        {
            false
        }
    }

    /// Calls `f` with the name and value of each response header of the
    /// list of headers (nginx keeps some outside of it, see the other
    /// methods).
    pub fn for_each_header_out(&self, mut f: impl FnMut(&[u8], &[u8])) {
        // SAFETY: the request's list of response headers.
        unsafe { for_each_header(&(*self.as_ptr()).headers_out.headers.part, |name, value| f(name, value.as_bytes())) };
    }

    fn core_loc_conf(&self) -> *mut ngx_http_core_loc_conf_t {
        // SAFETY: loc_conf has an entry for the core module.
        unsafe {
            *(*self.as_ptr()).loc_conf.add((*ptr::addr_of!(ngx_http_core_module)).ctx_index)
                as *mut ngx_http_core_loc_conf_t
        }
    }

    /// The `Server` header nginx will send.
    pub fn server_header(&self) -> Vec<u8> {
        // SAFETY: reads of a valid request and its core configuration.
        unsafe {
            let r = self.as_ptr();
            if !(*r).headers_out.server.is_null() {
                return (*(*r).headers_out.server).value.as_bytes().to_vec();
            }
            if (*self.core_loc_conf()).server_tokens != 0 { NGINX_VER.to_bytes().to_vec() } else { b"nginx".to_vec() }
        }
    }

    /// The `Date` header nginx will send.
    pub fn date_header(&self) -> Vec<u8> {
        // SAFETY: reads of a valid request; ngx_cached_http_time is
        // maintained by nginx.
        unsafe {
            let r = self.as_ptr();
            if (*r).headers_out.date.is_null() {
                let t: ngx_str_t = ptr::read_volatile(ptr::addr_of!(ngx_cached_http_time));
                t.as_bytes().to_vec()
            } else {
                (*(*r).headers_out.date).value.as_bytes().to_vec()
            }
        }
    }

    /// The length of the response body, when nginx knows it and it is not
    /// empty.
    pub fn content_length(&self) -> Option<nginx_sys::off_t> {
        // SAFETY: a read of a valid request.
        let n = unsafe { (*self.as_ptr()).headers_out.content_length_n };
        (n > 0).then_some(n)
    }

    /// The `Content-Type` of the response, when it has one.
    pub fn content_type(&self) -> Option<Vec<u8>> {
        // SAFETY: a read of a valid request.
        unsafe {
            let r = self.as_ptr();
            ((*r).headers_out.content_type.len > 0).then(|| (*r).headers_out.content_type.as_bytes().to_vec())
        }
    }

    /// The `Last-Modified` header nginx will send, when it sends one.
    pub fn last_modified_header(&self) -> Option<Vec<u8>> {
        // SAFETY: a read of a valid request; ngx_http_time writes at most
        // 29 bytes.
        unsafe {
            let r = self.as_ptr();
            if (*r).headers_out.last_modified_time == -1 {
                return None;
            }
            let mut buf = [0u8; 1024];
            let p = ngx_http_time(buf.as_mut_ptr(), (*r).headers_out.last_modified_time);
            let len = p.offset_from(buf.as_ptr()) as usize;
            Some(buf[..len].to_vec())
        }
    }

    /// Whether the response is `101 Switching Protocols`.
    pub fn is_upgrade(&self) -> bool {
        // SAFETY: a read of a valid request.
        unsafe { (*self.as_ptr()).headers_out.status == NGX_HTTP_SWITCHING_PROTOCOLS as usize }
    }

    /// Whether the connection is kept alive after the response.
    pub fn keepalive(&self) -> bool {
        // SAFETY: a read of a valid request.
        unsafe { (*self.as_ptr()).keepalive() != 0 }
    }

    /// `keepalive_timeout`'s second parameter: the timeout nginx announces
    /// in a `Keep-Alive` header, when it does.
    pub fn keepalive_header_timeout(&self) -> Option<nginx_sys::time_t> {
        // SAFETY: a read of the core configuration.
        let timeout = unsafe { (*self.core_loc_conf()).keepalive_header };
        (timeout != 0).then_some(timeout)
    }

    /// Whether the response body is sent in chunks.
    pub fn chunked(&self) -> bool {
        // SAFETY: a read of a valid request.
        unsafe { (*self.as_ptr()).chunked() != 0 }
    }

    /// Whether nginx adds `Vary: Accept-Encoding` (`gzip_vary`).
    pub fn gzip_vary(&self) -> bool {
        #[cfg(ngx_feature = "http_gzip")]
        {
            // SAFETY: reads of a valid request and its core configuration.
            unsafe { (*self.as_ptr()).gzip_vary() != 0 && (*self.core_loc_conf()).gzip_vary != 0 }
        }
        #[cfg(not(ngx_feature = "http_gzip"))]
        {
            false
        }
    }

    /// `ngx_http_finalize_request(r, rc)`: ends the request (outside of
    /// the phase handlers, which return `rc` instead).
    pub fn finalize(&self, rc: ngx_int_t) {
        // SAFETY: a valid request.
        unsafe { nginx_sys::ngx_http_finalize_request(self.as_ptr(), rc) }
    }

    /// `ngx_http_filter_finalize_request(r, module, rc)`: ends the request
    /// from a filter, with the response `rc`.
    ///
    /// # Safety
    /// `module` must be the module the filter belongs to.
    pub unsafe fn finalize_from_filter(&self, module: *mut ngx_module_t, rc: ngx_int_t) -> ngx_int_t {
        // SAFETY: a valid request, in a filter of `module`.
        unsafe { ngx_http_filter_finalize_request(self.as_ptr(), module, rc) }
    }
}
