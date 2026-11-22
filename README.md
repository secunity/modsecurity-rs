# libmodsecurity in Rust

A Rust implementation of [libmodsecurity v3](https://github.com/owasp-modsecurity/ModSecurity),
the ModSecurity web application firewall engine. It loads SecLang rule sets
(such as the OWASP Core Rule Set) and inspects the HTTP transactions a
connector hands it.

- It passes the test suites of the original ModSecurity and the OWASP CRS
  regression suite.
- It keeps the C API (`msc_*`) and the `libmodsecurity.so.3` SONAME, so
  existing connectors can use it in place of the C++ library.
- Where it behaves differently from C++, [MIGRATION.md](MIGRATION.md) says so.

## Build

```sh
cargo build --release
```

This builds `target/release/libmodsecurity.{so,a}` (the C API) and the
`modsecurity` Rust crate. PCRE2 is required. Optional components are cargo
features, all on by default: `libxml2`, `lua`, `maxmind`, `lmdb`, `ssdeep`,
`curl` (`libxml2`, `ssdeep` and `curl` need the system libraries).
`--no-default-features` builds the core alone.

## Use from Rust

```rust
use modsecurity::inspection::Inspection;
use modsecurity::{ModSecurity, RulesSet};

let engine = ModSecurity::new();
let mut rules = RulesSet::new();
rules.load_from_uri("modsecurity.conf").ok();

// Each step returns `Err(Blocked)` when the rules interrupt the exchange.
let outcome = (|| {
    let client = "10.0.0.7:51234".parse().unwrap();
    let server = "10.0.0.1:80".parse().unwrap();
    let head = Inspection::new(&engine, &rules).connection(client, server)?;
    let body = head.request_head(b"GET", b"/?id=1", b"1.1", [("Host", "example.com")])?;
    let response = body.finish()?;
    response.response_head(200, "HTTP 1.1", [("Content-Type", "text/html")])?.finish()
})();
if let Err(blocked) = outcome {
    println!("blocked with status {}", blocked.intervention().status);
}
```

With the `tower` feature, `modsecurity::middleware::ModSecurityLayer` wraps
any tower service (axum, hyper, ...). See `examples/axum`.

## Test

```sh
cargo test
```

This runs the unit tests and the original ModSecurity regression and unit
suites. `test/crs/run.sh` runs the OWASP CRS suite through nginx.

## nginx connector

`connectors/nginx` is the ModSecurity-nginx module in Rust. See
[connectors/nginx/README.md](connectors/nginx/README.md).

## More

- [ARCHITECTURE.md](ARCHITECTURE.md): how the code is organised
- [MIGRATION.md](MIGRATION.md): differences from the C++ library
- [REFACTORING.md](REFACTORING.md): design history

## License

Apache License 2.0 (see `LICENSE`).
