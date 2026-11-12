//! Port of `src/ngx_http_modsecurity_module.c`: module definition,
//! directives, configuration, request context and intervention handling.

use core::ffi::{c_char, c_void};
use core::mem::offset_of;
use core::ptr;

use modsecurity::intervention::{self, ModSecurityIntervention};
use modsecurity::modsecurity::{
    MODSECURITY_MAJOR, MODSECURITY_MINOR, MODSECURITY_PATCHLEVEL, ModSecurity, ServerLogEntry,
};
use modsecurity::rules_set::RulesSet;
use modsecurity::transaction::Transaction;
use nginx_sys::{
    NGX_CONF_1MORE, NGX_CONF_FLAG, NGX_CONF_TAKE1, NGX_CONF_TAKE2, NGX_CONF_UNSET, NGX_HTTP_INTERNAL_SERVER_ERROR,
    NGX_HTTP_LOC_CONF, NGX_HTTP_LOC_CONF_OFFSET, NGX_HTTP_MAIN_CONF, NGX_HTTP_MODULE, NGX_HTTP_SRV_CONF, NGX_LOG_ERR,
    NGX_LOG_NOTICE, NGX_OK, ngx_array_push, ngx_command_t, ngx_conf_set_flag_slot, ngx_conf_t, ngx_flag_t,
    ngx_http_compile_complex_value, ngx_http_compile_complex_value_t, ngx_http_complex_value, ngx_http_complex_value_t,
    ngx_http_conf_ctx_t, ngx_http_core_main_conf_t, ngx_http_core_module, ngx_http_handler_pt, ngx_http_module_t,
    ngx_http_phases_NGX_HTTP_ACCESS_PHASE, ngx_http_phases_NGX_HTTP_LOG_PHASE, ngx_http_request_t, ngx_int_t,
    ngx_list_push, ngx_module_t, ngx_palloc, ngx_pnalloc, ngx_pool_cleanup_add, ngx_str_t, ngx_table_elt_t, ngx_uint_t,
};
use ngx::core::Pool;

use crate::ngx_http_modsecurity_access::ngx_http_modsecurity_access_handler;
use crate::ngx_http_modsecurity_body_filter::ngx_http_modsecurity_body_filter_init;
use crate::ngx_http_modsecurity_common::{Ctx, LocConf, MODSECURITY_NGINX_WHOAMI, MainConf, NgxLog, log_error};
use crate::ngx_http_modsecurity_header_filter::ngx_http_modsecurity_header_filter_init;
use crate::ngx_http_modsecurity_log::{ngx_http_modsecurity_log, ngx_http_modsecurity_log_handler, process_logging};

/// `NGX_CONF_UNSET_PTR`
const NGX_CONF_UNSET_PTR: *mut ngx_http_complex_value_t = usize::MAX as *mut ngx_http_complex_value_t;
/// `NGX_CONF_OK`
const NGX_CONF_OK: *mut c_char = ptr::null_mut();
/// `NGX_CONF_ERROR`
const NGX_CONF_ERROR: *mut c_char = usize::MAX as *mut c_char;

// ---------------------------------------------------------------------------
// Configuration access helpers (the ngx_http_get_module_*_conf macros)
// ---------------------------------------------------------------------------

/// `ngx_http_get_module_loc_conf(r, ngx_http_modsecurity_module)`
///
/// # Safety
/// `r` must be a valid request.
pub unsafe fn loc_conf(r: *mut ngx_http_request_t) -> *mut LocConf {
    // SAFETY: loc_conf has an entry for every HTTP module's ctx_index.
    unsafe { *(*r).loc_conf.add((*ptr::addr_of!(ngx_http_modsecurity_module)).ctx_index) as *mut LocConf }
}

/// `ngx_http_get_module_main_conf(r, ngx_http_modsecurity_module)`
///
/// # Safety
/// `r` must be a valid request.
pub unsafe fn main_conf(r: *mut ngx_http_request_t) -> *mut MainConf {
    // SAFETY: as above.
    unsafe { *(*r).main_conf.add((*ptr::addr_of!(ngx_http_modsecurity_module)).ctx_index) as *mut MainConf }
}

/// `ngx_http_conf_get_module_main_conf(cf, module)`
///
/// # Safety
/// `cf` must be an HTTP configuration context.
unsafe fn conf_main_conf(cf: *mut ngx_conf_t, module: *const ngx_module_t) -> *mut c_void {
    // SAFETY: in the http block cf->ctx is an ngx_http_conf_ctx_t.
    unsafe {
        let ctx = (*cf).ctx as *mut ngx_http_conf_ctx_t;
        *(*ctx).main_conf.add((*module).ctx_index)
    }
}

/// `ngx_str_to_char`, returning an owned copy; the C helper returns NULL
/// for an empty string.
fn ngx_str_to_bytes(a: &ngx_str_t) -> Option<Vec<u8>> {
    if a.len == 0 {
        return None;
    }
    Some(a.as_bytes().to_vec())
}

/// Copies `s` into `pool` as a NUL terminated string (directive error
/// messages returned to nginx; the C code returns a `strdup`ed string).
///
/// # Safety
/// `pool` must be a valid pool.
unsafe fn pool_cstr(pool: *mut nginx_sys::ngx_pool_t, s: &str) -> *mut c_char {
    let bytes = s.as_bytes();
    let end = bytes.iter().position(|&c| c == 0).unwrap_or(bytes.len());
    // SAFETY: allocates end + 1 bytes from the pool and fills them.
    unsafe {
        let p = ngx_pnalloc(pool, end + 1) as *mut u8;
        if p.is_null() {
            return NGX_CONF_ERROR;
        }
        ptr::copy_nonoverlapping(bytes.as_ptr(), p, end);
        *p.add(end) = 0;
        p as *mut c_char
    }
}

// ---------------------------------------------------------------------------
// Interventions
// ---------------------------------------------------------------------------

/// `ngx_http_modsecurity_process_intervention`: applies a pending
/// intervention to the request. Returns the HTTP status to finalize with
/// (> 0), 0 when there is nothing to do, or -1 when the response headers
/// were already sent.
///
/// The C function takes the transaction and fetches the context again; the
/// transaction always is the context's, so the context is passed instead.
///
/// # Safety
/// `r` must be a valid request and `ctx` its context.
pub unsafe fn ngx_http_modsecurity_process_intervention(
    ctx: &mut Ctx,
    r: *mut ngx_http_request_t,
    early_log: bool,
) -> ngx_int_t {
    let mut it = ModSecurityIntervention { status: 200, ..Default::default() };

    if !ctx.modsec_transaction.intervention(&mut it) {
        return 0;
    }

    // SAFETY: valid request per the contract.
    let mcf = unsafe { loc_conf(r) };
    if mcf.is_null() {
        intervention::free(&mut it);
        return NGX_HTTP_INTERNAL_SERVER_ERROR as ngx_int_t;
    }

    // logging to nginx error log can be disable by setting
    // `modsecurity_use_error_log` to off
    // SAFETY: mcf checked above; r->connection->log is valid.
    unsafe {
        if (*mcf).use_error_log != 0 {
            let log = cstr_bytes(it.log).unwrap_or_else(|| b"(no log message was specified)".to_vec());
            log_error(NGX_LOG_ERR as ngx_uint_t, (*(*r).connection).log, &log);
        }
    }

    let url = cstr_bytes(it.url);
    let status = it.status;
    intervention::free(&mut it);

    if let Some(url) = url {
        // SAFETY: valid request; the header is allocated from its pool.
        unsafe {
            if (*r).header_sent() != 0 {
                return -1;
            }

            // Not sure if it sane to do this indepent of the phase but,
            // here we go... This code cames from
            // http/ngx_http_special_response.c (ngx_http_send_error_page);
            // src/http/ngx_http_core_module.c shows that location->hash
            // should be set to 1.
            ngx_http_clear_location(r);

            let data = ngx_pnalloc((*r).pool, url.len()) as *mut u8;
            let location = ngx_list_push(&mut (*r).headers_out.headers) as *mut ngx_table_elt_t;
            if data.is_null() || location.is_null() {
                return NGX_HTTP_INTERNAL_SERVER_ERROR as ngx_int_t;
            }
            ptr::copy_nonoverlapping(url.as_ptr(), data, url.len());
            ptr::write_bytes(location, 0, 1);
            (*location).key = ngx_str_t { len: 8, data: c"Location".as_ptr() as *mut u8 };
            (*location).value = ngx_str_t { len: url.len(), data };
            (*r).headers_out.location = location;
            (*(*r).headers_out.location).hash = 1;

            #[cfg(feature = "sanity-checks")]
            crate::ngx_http_modsecurity_header_filter::ngx_http_modsecurity_store_ctx_header(
                ctx,
                r,
                &(*location).key,
                &(*location).value,
            );
        }
        return status as ngx_int_t;
    }

    if status != 200 {
        // FIXME (C): this will bring proper response code to audit log in
        // case when e.g. error_page redirect was triggered, but there still
        // won't be another required pieces like response headers etc.
        ctx.modsec_transaction.update_status_code(status);

        if early_log {
            process_logging(ctx);
            ctx.logged = true;
        }

        // SAFETY: valid request.
        if unsafe { (*r).header_sent() } != 0 {
            return -1;
        }
        return status as ngx_int_t;
    }
    0
}

/// The bytes of a C string owned by the intervention (None for NULL).
fn cstr_bytes(p: *const c_char) -> Option<Vec<u8>> {
    if p.is_null() {
        return None;
    }
    // SAFETY: non-null intervention strings are NUL terminated (malloc'ed by
    // libmodsecurity).
    Some(unsafe { core::ffi::CStr::from_ptr(p) }.to_bytes().to_vec())
}

/// `ngx_http_clear_location(r)`
///
/// # Safety
/// `r` must be a valid request.
unsafe fn ngx_http_clear_location(r: *mut ngx_http_request_t) {
    // SAFETY: valid request.
    unsafe {
        if !(*r).headers_out.location.is_null() {
            (*(*r).headers_out.location).hash = 0;
            (*r).headers_out.location = ptr::null_mut();
        }
    }
}

// ---------------------------------------------------------------------------
// Request context
// ---------------------------------------------------------------------------

/// `ngx_http_modsecurity_cleanup`: request pool cleanup releasing the
/// context (and with it the transaction).
///
/// # Safety
/// Called by nginx with the context pointer registered in `create_ctx`.
pub unsafe extern "C" fn ngx_http_modsecurity_cleanup(data: *mut c_void) {
    if !data.is_null() {
        // SAFETY: data is the Box<Ctx> leaked by create_ctx, released once.
        drop(unsafe { Box::from_raw(data as *mut Ctx) });
    }
}

/// The cleanup handler as registered on request pools. Requests are
/// recognised by this exact value (see `ngx_http_modsecurity_get_module_ctx`),
/// so it is taken from one static rather than from the function item at each
/// use (Rust does not guarantee a function has a single address).
static CLEANUP_HANDLER: unsafe extern "C" fn(*mut c_void) = ngx_http_modsecurity_cleanup;

/// `ngx_http_modsecurity_create_ctx`
///
/// # Safety
/// `r` must be a valid request of a location where the module is enabled.
pub unsafe fn ngx_http_modsecurity_create_ctx(r: *mut ngx_http_request_t) -> *mut Ctx {
    // SAFETY: valid request; the configurations belong to the current cycle.
    unsafe {
        let mmcf = main_conf(r);
        let mcf = loc_conf(r);

        // SAFETY (lifetime): the ModSecurity instance and the rule set live
        // in nginx's configuration pool, which outlives every request served
        // with that configuration (the C module relies on the same
        // guarantee with raw pointers). The transaction is dropped by the
        // request pool cleanup below, before the configuration can go away.
        let ms: &'static ModSecurity = &*ptr::addr_of!((*mmcf).modsec);
        let rules: &'static RulesSet = &*ptr::addr_of!((*mcf).rules_set);
        let log = Some(Box::new(NgxLog((*(*r).connection).log)) as Box<dyn core::any::Any + Send>);

        let transaction = if !(*mcf).transaction_id.is_null() {
            let mut s = ngx_str_t::empty();
            if ngx_http_complex_value(r, (*mcf).transaction_id, &mut s) != NGX_OK as ngx_int_t {
                return ptr::null_mut();
            }
            let id = String::from_utf8_lossy(s.as_bytes()).into_owned();
            Transaction::with_id(ms, rules, &id, log)
        } else {
            Transaction::new(ms, rules, log)
        };

        let ctx = Box::into_raw(Box::new(Ctx {
            r,
            modsec_transaction: transaction,
            #[cfg(feature = "sanity-checks")]
            sanity_headers_out: Vec::with_capacity(12),
            waiting_more_body: false,
            body_requested: false,
            processed: false,
            logged: false,
            intervention_triggered: false,
            request_body_processed: false,
        }));

        let cln = ngx_pool_cleanup_add((*r).pool, 0);
        if cln.is_null() {
            drop(Box::from_raw(ctx));
            return ptr::null_mut();
        }
        (*cln).handler = Some(CLEANUP_HANDLER);
        (*cln).data = ctx as *mut c_void;

        // ngx_http_set_ctx(r, ctx, ngx_http_modsecurity_module)
        *(*r).ctx.add((*ptr::addr_of!(ngx_http_modsecurity_module)).ctx_index) = ctx as *mut c_void;
        ctx
    }
}

/// `ngx_http_modsecurity_get_module_ctx`
///
/// # Safety
/// `r` must be a valid request.
pub unsafe fn ngx_http_modsecurity_get_module_ctx(r: *mut ngx_http_request_t) -> *mut Ctx {
    // SAFETY: valid request.
    unsafe {
        let ctx = *(*r).ctx.add((*ptr::addr_of!(ngx_http_modsecurity_module)).ctx_index) as *mut Ctx;
        if !ctx.is_null() {
            return ctx;
        }
        // refer <nginx>/src/http/modules/ngx_http_realip_module.c: if module
        // context was reset, the original address can still be found in the
        // cleanup handler.
        let mut cln = (*(*r).pool).cleanup;
        while !cln.is_null() {
            if (*cln).handler.is_some_and(|h| core::ptr::fn_addr_eq(h, CLEANUP_HANDLER)) {
                return (*cln).data as *mut Ctx;
            }
            cln = (*cln).next;
        }
        ptr::null_mut()
    }
}

// ---------------------------------------------------------------------------
// Directives
// ---------------------------------------------------------------------------

/// The value of the directive's `n`-th argument.
///
/// # Safety
/// `cf` must be a configuration with at least `n + 1` arguments.
unsafe fn arg(cf: *mut ngx_conf_t, n: usize) -> ngx_str_t {
    // SAFETY: per the contract.
    unsafe { *((*(*cf).args).elts as *mut ngx_str_t).add(n) }
}

/// Shared tail of the `modsecurity_rules*` setters: counts the loaded rules
/// or returns the parser error to nginx.
///
/// # Safety
/// `cf` must be the current configuration.
unsafe fn rules_result(
    cf: *mut ngx_conf_t,
    res: i32,
    mcf: *mut LocConf,
    counter: fn(&mut MainConf) -> &mut ngx_uint_t,
) -> *mut c_char {
    // SAFETY: cf and mcf are valid during directive handling.
    unsafe {
        if res < 0 {
            return pool_cstr((*cf).pool, &(*mcf).rules_set.get_parser_error());
        }
        let mmcf = conf_main_conf(cf, ptr::addr_of!(ngx_http_modsecurity_module)) as *mut MainConf;
        *counter(&mut *mmcf) += res as ngx_uint_t;
    }
    NGX_CONF_OK
}

/// `modsecurity_rules <rules>`
unsafe extern "C" fn ngx_conf_set_rules(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let mcf = conf as *mut LocConf;
    // SAFETY: nginx calls setters with a valid configuration and our conf.
    unsafe {
        let rules = ngx_str_to_bytes(&arg(cf, 1)).unwrap_or_default();
        let res = (*mcf).rules_set.load(&String::from_utf8_lossy(&rules));
        rules_result(cf, res, mcf, |m| &mut m.rules_inline)
    }
}

/// `modsecurity_rules_file <path>`
unsafe extern "C" fn ngx_conf_set_rules_file(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let mcf = conf as *mut LocConf;
    // SAFETY: as above.
    unsafe {
        let file = ngx_str_to_bytes(&arg(cf, 1)).unwrap_or_default();
        let res = (*mcf).rules_set.load_from_uri(&String::from_utf8_lossy(&file));
        rules_result(cf, res, mcf, |m| &mut m.rules_file)
    }
}

/// `modsecurity_rules_remote <key> <url>`
unsafe extern "C" fn ngx_conf_set_rules_remote(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let mcf = conf as *mut LocConf;
    // SAFETY: as above.
    unsafe {
        let key = ngx_str_to_bytes(&arg(cf, 1)).unwrap_or_default();
        let server = ngx_str_to_bytes(&arg(cf, 2)).unwrap_or_default();
        let res = (*mcf).rules_set.load_remote(&String::from_utf8_lossy(&key), &String::from_utf8_lossy(&server));
        rules_result(cf, res, mcf, |m| &mut m.rules_remote)
    }
}

/// `modsecurity_transaction_id <complex value>`
unsafe extern "C" fn ngx_conf_set_transaction_id(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let mcf = conf as *mut LocConf;
    // SAFETY: as above; the compiled value is copied into the conf pool.
    unsafe {
        let mut value = arg(cf, 1);
        let mut cv: ngx_http_complex_value_t = core::mem::zeroed();
        let mut ccv: ngx_http_compile_complex_value_t = core::mem::zeroed();
        ccv.cf = cf;
        ccv.value = &mut value;
        ccv.complex_value = &mut cv;
        ccv.set_zero(1);
        if ngx_http_compile_complex_value(&mut ccv) != NGX_OK as ngx_int_t {
            return NGX_CONF_ERROR;
        }
        let p =
            ngx_palloc((*cf).pool, core::mem::size_of::<ngx_http_complex_value_t>()) as *mut ngx_http_complex_value_t;
        if p.is_null() {
            return NGX_CONF_ERROR;
        }
        *p = cv;
        (*mcf).transaction_id = p;
    }
    NGX_CONF_OK
}

const fn ngx_string(s: &'static core::ffi::CStr) -> ngx_str_t {
    ngx_str_t { len: s.count_bytes(), data: s.as_ptr() as *mut u8 }
}

const ANY_CONF: u32 = NGX_HTTP_LOC_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_MAIN_CONF;

static mut NGX_HTTP_MODSECURITY_COMMANDS: [ngx_command_t; 7] = [
    ngx_command_t {
        name: ngx_string(c"modsecurity"),
        type_: (ANY_CONF | NGX_CONF_FLAG) as ngx_uint_t,
        set: Some(ngx_conf_set_flag_slot),
        conf: NGX_HTTP_LOC_CONF_OFFSET as ngx_uint_t,
        offset: offset_of!(LocConf, enable) as ngx_uint_t,
        post: ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string(c"modsecurity_rules"),
        type_: (ANY_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(ngx_conf_set_rules),
        conf: NGX_HTTP_LOC_CONF_OFFSET as ngx_uint_t,
        offset: offset_of!(LocConf, enable) as ngx_uint_t,
        post: ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string(c"modsecurity_rules_file"),
        type_: (ANY_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(ngx_conf_set_rules_file),
        conf: NGX_HTTP_LOC_CONF_OFFSET as ngx_uint_t,
        offset: offset_of!(LocConf, enable) as ngx_uint_t,
        post: ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string(c"modsecurity_rules_remote"),
        type_: (ANY_CONF | NGX_CONF_TAKE2) as ngx_uint_t,
        set: Some(ngx_conf_set_rules_remote),
        conf: NGX_HTTP_LOC_CONF_OFFSET as ngx_uint_t,
        offset: offset_of!(LocConf, enable) as ngx_uint_t,
        post: ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string(c"modsecurity_transaction_id"),
        type_: (ANY_CONF | NGX_CONF_1MORE) as ngx_uint_t,
        set: Some(ngx_conf_set_transaction_id),
        conf: NGX_HTTP_LOC_CONF_OFFSET as ngx_uint_t,
        offset: 0,
        post: ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string(c"modsecurity_use_error_log"),
        type_: (ANY_CONF | NGX_CONF_FLAG) as ngx_uint_t,
        set: Some(ngx_conf_set_flag_slot),
        conf: NGX_HTTP_LOC_CONF_OFFSET as ngx_uint_t,
        offset: offset_of!(LocConf, use_error_log) as ngx_uint_t,
        post: ptr::null_mut(),
    },
    ngx_command_t::empty(),
];

static NGX_HTTP_MODSECURITY_CTX: ngx_http_module_t = ngx_http_module_t {
    preconfiguration: None,
    postconfiguration: Some(ngx_http_modsecurity_init),
    create_main_conf: Some(ngx_http_modsecurity_create_main_conf),
    init_main_conf: Some(ngx_http_modsecurity_init_main_conf),
    create_srv_conf: None,
    merge_srv_conf: None,
    create_loc_conf: Some(ngx_http_modsecurity_create_conf),
    merge_loc_conf: Some(ngx_http_modsecurity_merge_conf),
};

/// `ngx_http_modsecurity_module`
#[used]
#[allow(non_upper_case_globals)]
#[cfg_attr(not(feature = "export-modules"), unsafe(no_mangle))]
pub static mut ngx_http_modsecurity_module: ngx_module_t = ngx_module_t {
    ctx: &raw const NGX_HTTP_MODSECURITY_CTX as _,
    commands: unsafe { &raw mut NGX_HTTP_MODSECURITY_COMMANDS[0] },
    type_: NGX_HTTP_MODULE as ngx_uint_t,
    ..ngx_module_t::default()
};

// ---------------------------------------------------------------------------
// Module callbacks
// ---------------------------------------------------------------------------

/// `ngx_http_modsecurity_init` (postconfiguration): registers the access and
/// log phase handlers and the header/body filters.
unsafe extern "C" fn ngx_http_modsecurity_init(cf: *mut ngx_conf_t) -> ngx_int_t {
    // SAFETY: called by nginx with the http configuration.
    unsafe {
        let cmcf = conf_main_conf(cf, ptr::addr_of!(ngx_http_core_module)) as *mut ngx_http_core_main_conf_t;
        if cmcf.is_null() {
            return nginx_sys::NGX_ERROR as ngx_int_t;
        }

        // We want to process everything in the NGX_HTTP_ACCESS_PHASE because
        // we need to allow ngx_http_limit_*_module to run.
        let h_access = ngx_array_push(&mut (*cmcf).phases[ngx_http_phases_NGX_HTTP_ACCESS_PHASE as usize].handlers)
            as *mut ngx_http_handler_pt;
        if h_access.is_null() {
            return nginx_sys::NGX_ERROR as ngx_int_t;
        }
        *h_access = Some(ngx_http_modsecurity_access_handler);

        // Process the log phase.
        //
        // TODO (C): check if the log phase happens like it happens on
        // Apache. check if last phase will not hold the request.
        let h_log = ngx_array_push(&mut (*cmcf).phases[ngx_http_phases_NGX_HTTP_LOG_PHASE as usize].handlers)
            as *mut ngx_http_handler_pt;
        if h_log.is_null() {
            return nginx_sys::NGX_ERROR as ngx_int_t;
        }
        *h_log = Some(ngx_http_modsecurity_log_handler);

        let rc = ngx_http_modsecurity_header_filter_init();
        if rc != NGX_OK as ngx_int_t {
            return rc;
        }
        ngx_http_modsecurity_body_filter_init()
    }
}

/// `ngx_http_modsecurity_create_main_conf`: creates the ModSecurity
/// instance. It is released with the configuration pool (C:
/// `ngx_http_modsecurity_cleanup_instance`).
unsafe extern "C" fn ngx_http_modsecurity_create_main_conf(cf: *mut ngx_conf_t) -> *mut c_void {
    // SAFETY: called by nginx with a valid configuration.
    let pool = unsafe { Pool::from_ngx_pool((*cf).pool) };
    let mut modsec = ModSecurity::new();
    // Provide our connector information to LibModSecurity
    modsec.set_connector_information(MODSECURITY_NGINX_WHOAMI);
    modsec.set_server_log_cb(Box::new(|data, entry| {
        let log = data.and_then(|d| d.downcast_ref::<NgxLog>()).map(|l| l.0);
        if let (Some(log), ServerLogEntry::Text(msg)) = (log, entry) {
            // SAFETY: the log belongs to the request being processed.
            unsafe { ngx_http_modsecurity_log(log, msg) };
        }
    }));
    let conf = MainConf { pool: pool.as_ptr(), modsec, rules_inline: 0, rules_file: 0, rules_remote: 0 };
    let p = pool.allocate(conf);
    if p.is_null() { NGX_CONF_ERROR as *mut c_void } else { p as *mut c_void }
}

/// `ngx_http_modsecurity_init_main_conf`
unsafe extern "C" fn ngx_http_modsecurity_init_main_conf(cf: *mut ngx_conf_t, conf: *mut c_void) -> *mut c_char {
    let mmcf = conf as *mut MainConf;
    // SAFETY: called by nginx with our main conf.
    unsafe {
        log_error(
            NGX_LOG_NOTICE as ngx_uint_t,
            (*cf).log,
            format!(
                "{} (rules loaded inline/local/remote: {}/{}/{})",
                MODSECURITY_NGINX_WHOAMI,
                (*mmcf).rules_inline,
                (*mmcf).rules_file,
                (*mmcf).rules_remote
            )
            .as_bytes(),
        );
        log_error(
            NGX_LOG_NOTICE as ngx_uint_t,
            (*cf).log,
            format!("libmodsecurity3 version {}.{}.{}", MODSECURITY_MAJOR, MODSECURITY_MINOR, MODSECURITY_PATCHLEVEL)
                .as_bytes(),
        );
    }
    NGX_CONF_OK
}

/// `ngx_http_modsecurity_create_conf`: per-location configuration with its
/// own rule set (released with the pool; C:
/// `ngx_http_modsecurity_cleanup_rules`).
unsafe extern "C" fn ngx_http_modsecurity_create_conf(cf: *mut ngx_conf_t) -> *mut c_void {
    // SAFETY: called by nginx with a valid configuration.
    let pool = unsafe { Pool::from_ngx_pool((*cf).pool) };
    let conf = LocConf {
        pool: pool.as_ptr(),
        rules_set: RulesSet::new(),
        enable: NGX_CONF_UNSET as ngx_flag_t,
        use_error_log: NGX_CONF_UNSET as ngx_flag_t,
        #[cfg(feature = "sanity-checks")]
        sanity_checks_enabled: NGX_CONF_UNSET as ngx_flag_t,
        transaction_id: NGX_CONF_UNSET_PTR,
    };
    let p = pool.allocate(conf);
    if p.is_null() { NGX_CONF_ERROR as *mut c_void } else { p as *mut c_void }
}

/// `ngx_conf_merge_value(conf, prev, default)`
fn merge_value(conf: &mut ngx_flag_t, prev: ngx_flag_t, default: ngx_flag_t) {
    if *conf == NGX_CONF_UNSET as ngx_flag_t {
        *conf = if prev == NGX_CONF_UNSET as ngx_flag_t { default } else { prev };
    }
}

/// `ngx_http_modsecurity_merge_conf`: inherits the flags and appends the
/// parent's rules to the child's (`msc_rules_merge(child, parent)`).
unsafe extern "C" fn ngx_http_modsecurity_merge_conf(
    cf: *mut ngx_conf_t,
    parent: *mut c_void,
    child: *mut c_void,
) -> *mut c_char {
    let p = parent as *mut LocConf;
    let c = child as *mut LocConf;
    // SAFETY: nginx passes two distinct location configurations of ours.
    unsafe {
        let (p, c) = (&mut *p, &mut *c);
        merge_value(&mut c.enable, p.enable, 0);
        // ngx_conf_merge_ptr_value(c->transaction_id, p->transaction_id, NULL)
        if c.transaction_id == NGX_CONF_UNSET_PTR {
            c.transaction_id = if p.transaction_id == NGX_CONF_UNSET_PTR { ptr::null_mut() } else { p.transaction_id };
        }
        merge_value(&mut c.use_error_log, p.use_error_log, 1);
        #[cfg(feature = "sanity-checks")]
        merge_value(&mut c.sanity_checks_enabled, p.sanity_checks_enabled, 0);

        #[cfg(feature = "ddebug")]
        {
            p.rules_set.dump();
            c.rules_set.dump();
        }

        let rules = c.rules_set.merge(&mut p.rules_set);
        if rules < 0 {
            return pool_cstr((*cf).pool, &c.rules_set.get_parser_error());
        }

        #[cfg(feature = "ddebug")]
        c.rules_set.dump();
    }
    NGX_CONF_OK
}
