//! The nginx connector for ModSecurity: a dynamic nginx module on top of
//! the `modsecurity` crate.
//!
//! ```nginx
//! load_module modules/ngx_http_modsecurity_module.so;
//!
//! http {
//!     modsecurity on;
//!     modsecurity_rules_file /etc/nginx/modsec/main.conf;
//! }
//! ```
//!
//! The directives (`modsecurity`, `modsecurity_rules`,
//! `modsecurity_rules_file`, `modsecurity_rules_remote`,
//! `modsecurity_transaction_id`, `modsecurity_use_error_log`) and their
//! behaviour are those of the C module (ModSecurity-nginx v1.0.4).
//!
//! | module | what it has |
//! |---|---|
//! | [`module`] | the nginx module: its directives, configuration and handlers' registration |
//! | [`context`] | the configuration structures and the per-request context |
//! | [`access`] | the access phase handler: connection, request line, headers and body |
//! | [`header_filter`], [`body_filter`] | the response headers and body |
//! | [`log`] | the log phase handler |
//! | [`intervention`] | applying an intervention of ModSecurity to the request |
//! | [`nginx`] | nginx as the handlers see it: every access to its structures |

pub mod access;
pub mod body_filter;
pub mod context;
pub mod header_filter;
pub mod intervention;
pub mod log;
pub mod module;
pub mod nginx;

/// The tables nginx looks up in a dynamic module built outside its build
/// system (`ngx_modules`, `ngx_module_names`, `ngx_module_order`), as
/// `auto/module` generates them for the C module.
///
/// `ngx::ngx_modules!` exports an empty order, with which nginx appends the
/// module to the end of the list: its filters then run first in the output
/// chain, before the headers filter adds `add_header`/`expires` headers and
/// before the copy filter reads static files into memory. The order below is
/// the one of the C module's `config`: nginx places the module before every
/// module listed after its own name, which puts its filters after the copy,
/// headers and postpone filters and before gzip.
#[cfg(feature = "export-modules")]
mod exports {
    use core::ffi::c_char;

    use nginx_sys::ngx_module_t;

    use crate::module::ngx_http_modsecurity_module;

    /// A NULL terminated array of pointers, as nginx reads it.
    #[repr(transparent)]
    pub struct Table<T, const N: usize>([*const T; N]);

    // SAFETY: the tables are never written; nginx only reads them, while it
    // loads the module.
    unsafe impl<T, const N: usize> Sync for Table<T, N> {}

    #[unsafe(no_mangle)]
    #[allow(non_upper_case_globals)]
    pub static ngx_modules: Table<ngx_module_t, 2> = Table([&raw const ngx_http_modsecurity_module, core::ptr::null()]);

    #[unsafe(no_mangle)]
    #[allow(non_upper_case_globals)]
    pub static ngx_module_names: Table<c_char, 2> = Table([c"ngx_http_modsecurity_module".as_ptr(), core::ptr::null()]);

    #[unsafe(no_mangle)]
    #[allow(non_upper_case_globals)]
    pub static ngx_module_order: Table<c_char, 17> = Table([
        c"ngx_http_chunked_filter_module".as_ptr(),
        c"ngx_http_v2_filter_module".as_ptr(),
        c"ngx_http_range_header_filter_module".as_ptr(),
        c"ngx_http_gzip_filter_module".as_ptr(),
        c"ngx_http_modsecurity_module".as_ptr(),
        c"ngx_http_postpone_filter_module".as_ptr(),
        c"ngx_http_ssi_filter_module".as_ptr(),
        c"ngx_http_charset_filter_module".as_ptr(),
        c"ngx_http_xslt_filter_module".as_ptr(),
        c"ngx_http_image_filter_module".as_ptr(),
        c"ngx_http_sub_filter_module".as_ptr(),
        c"ngx_http_addition_filter_module".as_ptr(),
        c"ngx_http_gunzip_filter_module".as_ptr(),
        c"ngx_http_userid_filter_module".as_ptr(),
        c"ngx_http_headers_filter_module".as_ptr(),
        c"ngx_http_copy_filter_module".as_ptr(),
        core::ptr::null(),
    ]);
}
