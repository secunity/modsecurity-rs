//! The nginx module: its definition, its directives and configuration, and
//! the registration of its handlers and filters.

use core::ffi::{c_char, c_void};
use core::mem::offset_of;
use core::ptr;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use modsecurity::{
    LoadError, MODSECURITY_MAJOR, MODSECURITY_MINOR, MODSECURITY_PATCHLEVEL, ModSecurity, RulesSet, ServerLogEntry,
};
use nginx_sys::{
    NGX_CONF_1MORE, NGX_CONF_FLAG, NGX_CONF_TAKE1, NGX_CONF_TAKE2, NGX_CONF_UNSET, NGX_HTTP_LOC_CONF,
    NGX_HTTP_LOC_CONF_OFFSET, NGX_HTTP_MAIN_CONF, NGX_HTTP_MODULE, NGX_HTTP_SRV_CONF, NGX_LOG_INFO, NGX_LOG_NOTICE,
    NGX_OK, ngx_array_push, ngx_command_t, ngx_conf_set_flag_slot, ngx_conf_t, ngx_flag_t,
    ngx_http_compile_complex_value, ngx_http_compile_complex_value_t, ngx_http_complex_value_t, ngx_http_conf_ctx_t,
    ngx_http_core_main_conf_t, ngx_http_core_module, ngx_http_handler_pt, ngx_http_module_t,
    ngx_http_phases_NGX_HTTP_ACCESS_PHASE, ngx_http_phases_NGX_HTTP_LOG_PHASE, ngx_int_t, ngx_module_t, ngx_palloc,
    ngx_pnalloc, ngx_str_t, ngx_uint_t,
};
use ngx::core::Pool;

use crate::access::ngx_http_modsecurity_access_handler;
use crate::body_filter::ngx_http_modsecurity_body_filter_init;
use crate::context::{LocConf, MODSECURITY_NGINX_WHOAMI, MainConf};
use crate::header_filter::ngx_http_modsecurity_header_filter_init;
use crate::log::ngx_http_modsecurity_log_handler;
use crate::nginx::{Log, catch_panic};

/// `NGX_CONF_UNSET_PTR`
const NGX_CONF_UNSET_PTR: *mut ngx_http_complex_value_t = usize::MAX as *mut ngx_http_complex_value_t;
/// `NGX_CONF_OK`
const NGX_CONF_OK: *mut c_char = ptr::null_mut();
/// `NGX_CONF_ERROR`
const NGX_CONF_ERROR: *mut c_char = usize::MAX as *mut c_char;

// ---------------------------------------------------------------------------
// Configuration access helpers (the ngx_http_get_module_*_conf macros)
// ---------------------------------------------------------------------------

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
    let bytes = crate::nginx::c_str(s.as_bytes());
    let end = bytes.len();
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

/// [`catch_panic`] for a configuration callback: a panic is logged on the
/// configuration's log and gives `on_panic`.
///
/// # Safety
/// `cf` must be the configuration nginx called the callback with.
unsafe fn conf_catch_panic<T>(cf: *mut ngx_conf_t, handler: &str, on_panic: T, f: impl FnOnce() -> T) -> T {
    // SAFETY: a configuration has a log, valid while nginx configures.
    let log = unsafe { Log::new((*cf).log) };
    catch_panic(log, handler, || on_panic, f)
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
    res: Result<usize, LoadError>,
    counter: fn(&mut MainConf) -> &mut ngx_uint_t,
) -> *mut c_char {
    // SAFETY: cf is valid during directive handling.
    unsafe {
        let n = match res {
            Ok(n) => n,
            Err(error) => return pool_cstr((*cf).pool, error.message()),
        };
        let mmcf = conf_main_conf(cf, ptr::addr_of!(ngx_http_modsecurity_module)) as *mut MainConf;
        *counter(&mut *mmcf) += n as ngx_uint_t;
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
        conf_catch_panic(cf, "modsecurity_rules", NGX_CONF_ERROR, || {
            let rules = ngx_str_to_bytes(&arg(cf, 1)).unwrap_or_default();
            let res = (*mcf).rules_set.load_bytes(&rules, "");
            rules_result(cf, res, |m| &mut m.rules_inline)
        })
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
        conf_catch_panic(cf, "modsecurity_rules_file", NGX_CONF_ERROR, || {
            let file = ngx_str_to_bytes(&arg(cf, 1)).unwrap_or_default();
            let res = (*mcf).rules_set.load_file(Path::new(OsStr::from_bytes(&file)));
            rules_result(cf, res, |m| &mut m.rules_file)
        })
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
        conf_catch_panic(cf, "modsecurity_rules_remote", NGX_CONF_ERROR, || {
            let key = ngx_str_to_bytes(&arg(cf, 1)).unwrap_or_default();
            let server = ngx_str_to_bytes(&arg(cf, 2)).unwrap_or_default();
            // The key and the URL are text; the rules downloaded are bytes.
            let res = (*mcf).rules_set.load_remote(&String::from_utf8_lossy(&key), &String::from_utf8_lossy(&server));
            rules_result(cf, res, |m| &mut m.rules_remote)
        })
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
        conf_catch_panic(cf, "modsecurity_transaction_id", NGX_CONF_ERROR, || {
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
            let p = ngx_palloc((*cf).pool, core::mem::size_of::<ngx_http_complex_value_t>())
                as *mut ngx_http_complex_value_t;
            if p.is_null() {
                return NGX_CONF_ERROR;
            }
            *p = cv;
            (*mcf).transaction_id = p;
            NGX_CONF_OK
        })
    }
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
    unsafe { conf_catch_panic(cf, "postconfiguration", nginx_sys::NGX_ERROR as ngx_int_t, || init(cf)) }
}

/// The body of [`ngx_http_modsecurity_init`].
///
/// # Safety
/// `cf` must be the http configuration.
unsafe fn init(cf: *mut ngx_conf_t) -> ngx_int_t {
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
    unsafe { conf_catch_panic(cf, "create_main_conf", ptr::null_mut(), || create_main_conf(cf)) }
}

/// The body of [`ngx_http_modsecurity_create_main_conf`].
///
/// # Safety
/// `cf` must be a valid configuration.
unsafe fn create_main_conf(cf: *mut ngx_conf_t) -> *mut c_void {
    // SAFETY: called by nginx with a valid configuration.
    let pool = unsafe { Pool::from_ngx_pool((*cf).pool) };
    let mut modsec = ModSecurity::new();
    // Provide our connector information to LibModSecurity
    modsec.set_connector_information(MODSECURITY_NGINX_WHOAMI);
    modsec.set_server_log_cb(Box::new(|data, entry| {
        // The rule message goes to the error log of the request being
        // processed, at `info` level.
        let log = data.and_then(|d| d.downcast_ref::<Log>());
        if let (Some(log), ServerLogEntry::Text(msg)) = (log, entry) {
            log.error(NGX_LOG_INFO as ngx_uint_t, msg.as_bytes());
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
    unsafe { conf_catch_panic(cf, "init_main_conf", NGX_CONF_ERROR, || init_main_conf(cf, mmcf)) }
}

/// The body of [`ngx_http_modsecurity_init_main_conf`].
///
/// # Safety
/// `cf` must be a valid configuration and `mmcf` the module's main conf.
unsafe fn init_main_conf(cf: *mut ngx_conf_t, mmcf: *mut MainConf) -> *mut c_char {
    // SAFETY: per the contract.
    unsafe {
        Log::new((*cf).log).error(
            NGX_LOG_NOTICE as ngx_uint_t,
            format!(
                "{} (rules loaded inline/local/remote: {}/{}/{})",
                MODSECURITY_NGINX_WHOAMI,
                (*mmcf).rules_inline,
                (*mmcf).rules_file,
                (*mmcf).rules_remote
            )
            .as_bytes(),
        );
        Log::new((*cf).log).error(
            NGX_LOG_NOTICE as ngx_uint_t,
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
    unsafe { conf_catch_panic(cf, "create_loc_conf", ptr::null_mut(), || create_conf(cf)) }
}

/// The body of [`ngx_http_modsecurity_create_conf`].
///
/// # Safety
/// `cf` must be a valid configuration.
unsafe fn create_conf(cf: *mut ngx_conf_t) -> *mut c_void {
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
    // SAFETY: called by nginx with a valid configuration.
    unsafe { conf_catch_panic(cf, "merge_loc_conf", NGX_CONF_ERROR, || merge_conf(cf, parent, child)) }
}

/// The body of [`ngx_http_modsecurity_merge_conf`].
///
/// # Safety
/// `cf` must be a valid configuration, `parent` and `child` two distinct
/// location configurations of this module.
unsafe fn merge_conf(cf: *mut ngx_conf_t, parent: *mut c_void, child: *mut c_void) -> *mut c_char {
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

        if let Err(error) = c.rules_set.merge(&mut p.rules_set) {
            return pool_cstr((*cf).pool, error.message());
        }

        #[cfg(feature = "ddebug")]
        c.rules_set.dump();
    }
    NGX_CONF_OK
}
