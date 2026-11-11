//! ModSecurity-nginx, ported to Rust: the nginx connector for
//! libmodsecurity, built as a dynamic nginx module on top of the Rust
//! libmodsecurity port.
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
//! behaviour are the C module's. The module tree mirrors the C sources:
//!
//! | C | Rust |
//! |---|---|
//! | `ngx_http_modsecurity_common.h` | [`ngx_http_modsecurity_common`] |
//! | `ngx_http_modsecurity_module.c` | [`ngx_http_modsecurity_module`] |
//! | `ngx_http_modsecurity_access.c` | [`ngx_http_modsecurity_access`] |
//! | `ngx_http_modsecurity_header_filter.c` | [`ngx_http_modsecurity_header_filter`] |
//! | `ngx_http_modsecurity_body_filter.c` | [`ngx_http_modsecurity_body_filter`] |
//! | `ngx_http_modsecurity_log.c` | [`ngx_http_modsecurity_log`] |

pub mod ngx_http_modsecurity_access;
pub mod ngx_http_modsecurity_body_filter;
pub mod ngx_http_modsecurity_common;
pub mod ngx_http_modsecurity_header_filter;
pub mod ngx_http_modsecurity_log;
pub mod ngx_http_modsecurity_module;

// The `ngx_modules` table nginx looks up in a dynamic module built outside
// its build system.
#[cfg(feature = "export-modules")]
use ngx_http_modsecurity_module::ngx_http_modsecurity_module;
#[cfg(feature = "export-modules")]
ngx::ngx_modules!(ngx_http_modsecurity_module);
