# ModSecurity-nginx C → Rust migration notes

Source: ModSecurity-nginx v1.0.4 (commit `28bfa42`).

## Layout

| C | Rust |
|---|---|
| `src/ngx_http_modsecurity_common.h` | `src/ngx_http_modsecurity_common.rs` (versions, `Ctx`, `MainConf`, `LocConf`) |
| `src/ngx_http_modsecurity_module.c` | `src/ngx_http_modsecurity_module.rs` (module, directives, configuration, request context, interventions) |
| `src/ngx_http_modsecurity_access.c` | `src/ngx_http_modsecurity_access.rs` |
| `src/ngx_http_modsecurity_header_filter.c` | `src/ngx_http_modsecurity_header_filter.rs` |
| `src/ngx_http_modsecurity_body_filter.c` | `src/ngx_http_modsecurity_body_filter.rs` |
| `src/ngx_http_modsecurity_log.c` | `src/ngx_http_modsecurity_log.rs` |
| `config` (nginx build glue) | `Cargo.toml` + `build.rs` (ngx-rust / nginx-sys) |
| `src/ddebug.h` | the `ddebug` cargo feature (rule set dumps while merging) |

## Design

- **nginx bindings**: `nginx-sys`/`ngx` (ngx-rust) generate the nginx
  structures for the configured nginx tree; the module, its directives and
  its `ngx_http_module_t` are static tables equivalent to the C ones, and
  the on/off directives use nginx's own `ngx_conf_set_flag_slot`, so
  directive errors are reported identically.
- **libmodsecurity**: the C module calls the C API (`msc_*`); the port uses
  the Rust API of the libmodsecurity port directly (same operations, same
  order). The module therefore embeds the engine instead of linking
  `libmodsecurity.so.3`.
- **Ownership**: the `ModSecurity` instance (main conf) and each location's
  `RulesSet` are allocated in nginx's configuration pool and dropped by pool
  cleanups (C: `cleanup_instance`/`cleanup_rules`). The per-request context
  (with its `Transaction`) is boxed and dropped by a request pool cleanup,
  which is also how the context is found again after nginx resets module
  contexts (C: the realip-style lookup in
  `ngx_http_modsecurity_get_module_ctx`).
- **Lifetimes**: a Rust `Transaction` borrows its `ModSecurity` and
  `RulesSet`; they live in the configuration pool, which outlives every
  request of the cycle, so the borrow is extended to `'static` in
  `create_ctx` (documented `SAFETY` there) — the same contract the C module
  relies on with raw pointers.
- **Logging**: the transaction's log callback data is the request's
  connection log, as in C; messages are written with
  `ngx_log_error_core(level, log, 0, "%s", msg)`, so nginx truncates them the
  same way.

## Differences from the C module

- The PCRE (v1) allocator hooks (`ngx_http_modsecurity_pcre_malloc_init/
  done`) are not ported: they only exist for nginx built with legacy PCRE
  (they compile to no-ops with PCRE2, the default since nginx 1.21.5) and the
  Rust libmodsecurity uses PCRE2 with its own allocator.
- `delayed_intervention`, declared but never used in the C context, is not
  carried over.
- Crash paths of the C code fail cleanly instead: a failed request-pool
  cleanup registration or `$modsecurity_transaction_id` evaluation returns
  500 (C returns `NGX_CONF_ERROR` cast to a context pointer).
- The redirect `Location` value is copied into the request pool (C hands
  nginx the `malloc`ed string from libmodsecurity and never frees it), and
  the pushed header element is zero-initialised.

C behaviour kept on purpose: the location merge appends the parent's rules
after the child's (`msc_rules_merge(child, parent)`), the default `Server`
value passed to ModSecurity includes its terminating NUL byte (the C code
uses `sizeof`), and `Content-Length` is not cleared (commented out in C).

## Verification

- OWASP CRS v4.8.0 regression suite (go-ftw 1.0.3, nginx-overrides, the
  configuration of CRS's own `modsec3-nginx` CI service): 3876/3876 pass
  through nginx 1.28.0 with this module, as with the C module. The
  ModSecurity log lines of a full run are identical to those of the C
  module on the same library (27,231 lines; the only differences seen came
  from the test backend occasionally resetting connections on large request
  bodies, which happens with either module).
- `cargo clippy --all-targets` and `cargo fmt --check` are clean.

## Gaps

- The C module's own nginx-tests suite (`tests/*.t`, Test::Nginx) has not
  been run against this module yet (see README for how to run it).
