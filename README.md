# libmodsecurity (Rust port)

A Rust port of [libmodsecurity v3.0.17](https://github.com/owasp-modsecurity/ModSecurity),
the ModSecurity web application firewall engine: it loads SecLang rule sets
(e.g. the OWASP Core Rule Set) and inspects HTTP transactions handed to it by
a connector.

The port keeps the C++ project's structure (see [MIGRATION.md](MIGRATION.md)),
its behaviour, and its C API (`msc_*` functions), so existing C connectors can
link against the Rust library instead of the C++ one.

## Building

```sh
cargo build --release
```

This produces `target/release/libmodsecurity.{so,a}` (C API) and the Rust
library. The shared library's SONAME is `libmodsecurity.so.3`, as for the C++
library: install it under that name (e.g. `libmodsecurity.so.3` → the built
file) to replace the C++ library under an existing connector. Optional components are cargo features mirroring the C++ `configure`
options; all are on by default:

| feature | C++ option | needs |
|---|---|---|
| `libxml2` | `WITH_LIBXML2` | system libxml2 (XML body processor, `XML:` variable, `@validateDTD`, `@validateSchema`) |
| `lua` | `WITH_LUA` | nothing (Lua 5.4 is vendored by `mlua`) |
| `maxmind` | `WITH_MAXMIND` | nothing (`maxminddb` crate) |
| `lmdb` | `WITH_LMDB` | nothing (vendored) — persistent collections in `./modsec-shared-collections` |
| `ssdeep` | `WITH_SSDEEP` | system libfuzzy (`@fuzzyHash`) |
| `curl` | `WITH_CURL` | system libcurl (`SecRemoteRules`, HTTPS audit log, remote `@pmFromFile`/`@ipMatchFromFile`) |
| `regex-dollar-endonly` | `MODSEC_REGEX_DOLLAR_ENDONLY` | — (off by default) |

PCRE2 is required (linked through `pcre2-sys`). `cargo build --no-default-features`
builds the core without the optional components.

## Using it from Rust

```rust
use modsecurity::intervention::ModSecurityIntervention;
use modsecurity::modsecurity::ModSecurity;
use modsecurity::rules_set::RulesSet;
use modsecurity::transaction::Transaction;

let ms = ModSecurity::new();
let mut rules = RulesSet::new();
if rules.load_from_uri("modsecurity.conf") < 0 {
    eprintln!("{}", rules.get_parser_error());
}

let mut t = Transaction::new(&ms, &rules, None);
t.process_connection("10.0.0.7", 51234, "10.0.0.1", 80);
t.process_uri(b"/index.php?id=1", b"GET", b"1.1");
t.add_request_header(b"Host", b"www.example.com");
t.process_request_headers();
// ... request body, response headers/body, process_logging()
let mut it = ModSecurityIntervention::default();
if t.intervention(&mut it) {
    println!("status {}", it.status);
}
```

`ModSecurity` and `RulesSet` are `Send + Sync` (share them between worker
threads); a `Transaction` borrows both.

## Tests

```sh
cargo test                      # library unit tests + the ported C++ suites
cargo run --bin regression_tests  # from test/: SecLang regression cases
cargo run --bin unit_tests        # from test/: operator/transformation cases
```

`cargo test` runs the C++ project's regression suite (788 cases) and its
operator/transformation unit suite (4336 cases) through the ported test
utilities. `test/differential/run.sh` compares this library with a built C++
libmodsecurity on the OWASP CRS (see the script header), and `test/crs/run.sh`
runs the OWASP CRS regression suite (go-ftw) through a real nginx with the
ModSecurity-nginx connector on top of a given library (or with a prebuilt
module such as the Rust connector port).

`tools/rules-check` is the port of `modsec-rules-check`.

## License

Apache License 2.0, like the original project (see `LICENSE`).
`others/libinjection` is a vendored pure-Rust libinjection implementation
(crate `libinjection`) with its own license file.
