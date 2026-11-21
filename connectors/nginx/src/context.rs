//! Versions, the module's configuration structures, and the per-request
//! context with its creation and lookup.

use core::ffi::c_void;
use core::ptr;

use modsecurity::ModSecurity;
use modsecurity::RulesSet;
use modsecurity::Transaction;
use nginx_sys::{ngx_flag_t, ngx_http_complex_value_t, ngx_pool_t, ngx_uint_t};

use crate::module::ngx_http_modsecurity_module;
use crate::nginx::Request;

/// TAG_NUM:
///
/// Alpha  - 001
/// Beta   - 002
/// Dev    - 010
/// Rc1    - 051
/// Rc2    - 052
/// ...    - ...
/// Release- 100
pub const MODSECURITY_NGINX_MAJOR: &str = "1";
pub const MODSECURITY_NGINX_MINOR: &str = "0";
pub const MODSECURITY_NGINX_PATCHLEVEL: &str = "4";
pub const MODSECURITY_NGINX_TAG: &str = "";
pub const MODSECURITY_NGINX_TAG_NUM: &str = "100";
pub const MODSECURITY_NGINX_VERSION: &str = "1.0.4";
pub const MODSECURITY_NGINX_VERSION_NUM: &str = "104100";
pub const MODSECURITY_NGINX_WHOAMI: &str = "ModSecurity-nginx v1.0.4";

/// `ngx_http_modsecurity_header_t` (sanity checks): a header sent to
/// ModSecurity.
#[cfg(feature = "sanity-checks")]
pub struct Header {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

/// Per-request state (`ngx_http_modsecurity_ctx_t`).
///
/// The C struct is allocated from the request pool and its transaction is
/// freed by a pool cleanup; here the context is boxed and the same pool
/// cleanup drops it (see [`Ctx::create`]).
pub struct Ctx {
    pub modsec_transaction: Transaction<'static>,
    /// Should be filled with the headers that were sent to ModSecurity.
    ///
    /// The idea is to compare this set of headers with the headers that were
    /// sent to the client. This check was placed because we don't have
    /// control over other modules, thus, we may partially inspect the
    /// headers.
    #[cfg(feature = "sanity-checks")]
    pub sanity_headers_out: Vec<Header>,
    pub waiting_more_body: bool,
    pub body_requested: bool,
    pub processed: bool,
    pub logged: bool,
    pub intervention_triggered: bool,
    pub request_body_processed: bool,
}

/// `ngx_http_modsecurity_main_conf_t`
pub struct MainConf {
    pub pool: *mut ngx_pool_t,
    pub modsec: ModSecurity,
    pub rules_inline: ngx_uint_t,
    pub rules_file: ngx_uint_t,
    pub rules_remote: ngx_uint_t,
}

/// `ngx_http_modsecurity_conf_t`: per-location configuration. The flags are
/// `ngx_flag_t` so that nginx's `ngx_conf_set_flag_slot` sets them (and
/// reports errors) exactly as for the C module.
pub struct LocConf {
    pub pool: *mut ngx_pool_t,
    pub rules_set: RulesSet,
    pub enable: ngx_flag_t,
    pub use_error_log: ngx_flag_t,
    pub transaction_id: *mut ngx_http_complex_value_t,
}

/// The module's configuration of the location of `request`.
pub fn loc_conf<'r>(request: &Request<'r>) -> Option<&'r LocConf> {
    // SAFETY: the location configuration of this module is a `LocConf`
    // (`ngx_http_modsecurity_create_conf`).
    unsafe { request.loc_conf(ptr::addr_of!(ngx_http_modsecurity_module)) }
}

/// The module's main configuration.
fn main_conf<'r>(request: &Request<'r>) -> Option<&'r MainConf> {
    // SAFETY: the main configuration of this module is a `MainConf`
    // (`ngx_http_modsecurity_create_main_conf`).
    unsafe { request.main_conf(ptr::addr_of!(ngx_http_modsecurity_module)) }
}

/// Request pool cleanup releasing the context, and with it the
/// transaction (`ngx_http_modsecurity_cleanup`).
///
/// # Safety
/// Called by nginx with the context pointer registered in [`Ctx::create`].
pub unsafe extern "C" fn ngx_http_modsecurity_cleanup(data: *mut c_void) {
    if !data.is_null() {
        // SAFETY: data is the Box<Ctx> leaked by `create`, released once.
        let ctx = unsafe { Box::from_raw(data as *mut Ctx) };
        crate::nginx::catch_panic(crate::nginx::cycle_log(), "the request cleanup", || (), || drop(ctx));
    }
}

/// The cleanup handler as registered on request pools. Requests are
/// recognised by this exact value (see [`Ctx::find`]), so it is taken from
/// one static rather than from the function item at each use (Rust does
/// not guarantee a function has a single address).
static CLEANUP_HANDLER: unsafe extern "C" fn(*mut c_void) = ngx_http_modsecurity_cleanup;

impl Ctx {
    /// Creates the context of `request`, with its transaction, and gives
    /// it to the request's pool to release (`ngx_http_modsecurity_create_ctx`).
    /// Null when the location has no configuration of this module, when
    /// its `modsecurity_transaction_id` cannot be evaluated, or when nginx
    /// is out of memory.
    pub fn create(request: &Request<'_>) -> *mut Ctx {
        let (Some(main), Some(conf)) = (main_conf(request), loc_conf(request)) else {
            return ptr::null_mut();
        };

        // SAFETY (lifetime): the ModSecurity instance and the rule set live
        // in nginx's configuration pool, which outlives every request served
        // with that configuration (the C module relies on the same
        // guarantee with raw pointers). The transaction is dropped by the
        // request pool cleanup below, before the configuration can go away.
        let ms: &'static ModSecurity = unsafe { &*ptr::addr_of!(main.modsec) };
        // SAFETY: as above.
        let rules: &'static RulesSet = unsafe { &*ptr::addr_of!(conf.rules_set) };
        let log = Some(Box::new(request.log()) as Box<dyn core::any::Any + Send>);

        let transaction = if !conf.transaction_id.is_null() {
            // SAFETY: compiled by the `modsecurity_transaction_id` directive.
            let Some(id) = (unsafe { request.complex_value(conf.transaction_id) }) else {
                return ptr::null_mut();
            };
            Transaction::with_id(ms, rules, &String::from_utf8_lossy(&id), log)
        } else {
            Transaction::new(ms, rules, log)
        };

        let ctx = Box::into_raw(Box::new(Ctx {
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

        if !request.add_cleanup(CLEANUP_HANDLER, ctx as *mut c_void) {
            // SAFETY: the box made above, which nothing else has.
            drop(unsafe { Box::from_raw(ctx) });
            return ptr::null_mut();
        }

        // SAFETY: this module is an HTTP module.
        unsafe { request.set_module_ctx(ptr::addr_of!(ngx_http_modsecurity_module), ctx as *mut c_void) };
        ctx
    }

    /// The context of `request`, or null (`ngx_http_modsecurity_get_module_ctx`).
    ///
    /// A subrequest has none: the transaction is the client's request's,
    /// and a subrequest (an `auth_request`, an SSI include) is not that
    /// request. It shares the pool of its main request, so the lookup of
    /// the pool cleanup below would find the main request's context.
    pub fn find(request: &Request<'_>) -> *mut Ctx {
        // SAFETY: this module is an HTTP module.
        let ctx = unsafe { request.module_ctx(ptr::addr_of!(ngx_http_modsecurity_module)) } as *mut Ctx;
        if !ctx.is_null() || request.is_subrequest() {
            return ctx;
        }
        // refer <nginx>/src/http/modules/ngx_http_realip_module.c: if module
        // context was reset, the original address can still be found in the
        // cleanup handler.
        request.cleanup_data(CLEANUP_HANDLER).map_or(ptr::null_mut(), |data| data as *mut Ctx)
    }
}
