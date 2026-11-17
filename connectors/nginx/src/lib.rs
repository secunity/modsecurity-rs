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

// The `ngx_modules` table nginx looks up in a dynamic module built outside
// its build system.
#[cfg(feature = "export-modules")]
use module::ngx_http_modsecurity_module;
#[cfg(feature = "export-modules")]
ngx::ngx_modules!(ngx_http_modsecurity_module);
