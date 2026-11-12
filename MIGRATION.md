# C++ → Rust migration notes

Source: libmodsecurity v3.0.17 (`ModSecurity` repository, commit `1ebdc390`).

## Layout

The module tree mirrors the C++ tree; each `.h`/`.cc` pair became one `.rs`
file with the same name (hyphens become underscores).

| C++ | Rust |
|---|---|
| `headers/modsecurity/*.h` (public API) | `src/*.rs` (crate root): `modsecurity`, `transaction`, `rules_set`, `rules_set_properties`, `rules_set_phases`, `rules`, `rule`, `rule_with_actions`, `rule_with_operator`, `rule_unconditional`, `rule_marker`, `rule_message`, `rules_exceptions`, `intervention`, `variable_value`, `variable_origin`, `anchored_*` |
| `headers/modsecurity/actions/action.h` | `src/actions/action.rs` |
| `headers/modsecurity/collection/*.h` | `src/collection/{collection,collections}.rs` |
| `headers/modsecurity/audit_log.h`, `debug_log.h` | `src/audit_log/audit_log.rs`, `src/debug_log/debug_log.rs` |
| `src/actions/{,ctl,data,disruptive,transformations}/` | `src/actions/...` (same subdirectories) |
| `src/operators/`, `src/variables/` | `src/operators/`, `src/variables/` |
| `src/audit_log/writer/`, `src/collection/backend/` | same paths |
| `src/request_body_processor/`, `src/engine/lua.cc` | same paths |
| `src/parser/seclang-scanner.ll`, `seclang-parser.yy`, `driver.cc` | `src/parser/seclang_scanner.rs`, `seclang_parser.rs`, `driver.rs` |
| `src/utils/` | `src/utils/` (+ `json.rs`, `unordered_multimap.rs`, see below) |
| `others/libinjection` (C submodule) | `others/libinjection` (pure Rust crate) |
| `others/mbedtls` | `md-5` / `sha1` crates; base64 hand-ported in `src/utils/base64.rs` |
| `test/regression`, `test/unit`, `test/common` | `test/regression`, `test/unit`, `test/common` (+ `test/suites.rs` for `cargo test`) |
| `tools/rules-check` | `tools/rules-check` |
| ModSecurity-nginx v1.0.4 (separate repository) | `connectors/nginx` (workspace member; see its MIGRATION.md) |

Not ported: `src/debug_log_writer_agent.h` (declared, never defined or used),
`headers/modsecurity/rules_properties.h` (compatibility include),
`src/compat/msvc.h`, the `examples/` programs and the C++-only API (C++
connectors cannot link a Rust library; the C API is provided instead), and
the benchmark/fuzzer/valgrind tooling under `test/`, and
`tools/gen-html-entities.py` (it generates the C++ entity table; the Rust
table in `html_entity_decode.rs` was translated from its output).

Naming: snake_case, `m_` prefixes dropped (`m_ruleId` → `rule_id`,
`m_variableArgs` → `t.vars.args`). The C API keeps the exact C names.

## How C++ constructs were expressed

- **Byte strings.** `std::string` holds arbitrary bytes, so request data
  (keys, values, bodies, matches, collection contents) is `Vec<u8>`/`&[u8]`;
  configuration identifiers are `String`.
- **Class hierarchies.** Open, polymorphic families became traits with the
  base-class data in a struct: `Action`/`ActionBase`, `Transformation`,
  `Operator`/`OperatorBase`, `Variable`/`VariableBase`, `Collection`,
  `DebugLog`, audit `Writer`. Closed hierarchies became enums: `Rule`
  (`Marker` | `WithActions`) and `RuleWithActionsKind` (`Operator` |
  `Unconditional` | `Script`). `dynamic_cast` became `Any` downcasts or
  explicit trait hooks (e.g. `Variable::dynamic_name/dynamic_del/...`
  replace SetVar's casts to the six `*_DynamicElement` classes).
- **Macros.** `DEFINE_VARIABLE*` became `define_variable!` /
  `define_variable_dict!` (the dict form generates `Name::{DictElement,
  NoDictElement, DictElementRegexp}` because Rust macros cannot paste
  identifiers); `ms_dbg_a` became `ms_dbg_a!`.
- **Ownership and lifetimes.** `Transaction<'a>` borrows its `ModSecurity`
  and `RulesSet` for `'a` (C++ keeps raw pointers that must outlive it).
  Rules are `Arc<Rule>` because `RulesSet::merge` shares them between sets
  (C++ `shared_ptr`); default actions and rule-exception entries are `Arc`
  for the same reason. A chained rule owns its child (`Box`); the C++ child →
  parent back pointer became a flag plus the transaction's stack of chain
  ancestors (`t.chained_rule_parents`), which the `RULE` variable walks.
- **Self-reference.** C++ `RuleMessage` references both the rule and the
  transaction, and copies are stored in that transaction. The Rust
  `RuleMessage<'a>` borrows only the rule; the transaction is passed to its
  formatting methods.
- **Shared mutable state.** Persistent collections, the debug log, the
  shared-files registry and the GeoIP database are shared across
  transactions/threads, so they synchronise internally (`Mutex`/`RwLock`),
  as the C++ code does with mutexes. The only other interior mutability is
  a per-thread cache of PCRE2 match data/contexts (`utils::regex`; C++
  allocates them for every match).
- **Resolved values.** C++ resolution hands out heap-allocated
  `VariableValue` copies; here a `VariableValue` shares its data behind an
  `Arc` (copy-on-write for the rare changes), so resolving `ARGS` & co.
  for every rule does not copy the strings. `ARGS*` entries also keep their
  `ARGS*_NAMES` value, built when the argument is set instead of on every
  resolution of the proxy, and rule evaluation reuses per-transaction
  buffers (`Transaction::eval_scratch`). Results are unchanged (checked by
  the differential run); these only remove allocations.
- **Container iteration order.** `ARGS`, headers, cookies, ... and the
  in-memory `TX`/`IP`/... collections are C++
  `std::unordered_multimap<string, T, MyHash, MyEqual>`; their iteration
  order decides which target is evaluated first (and thus `MATCHED_VAR` and
  log contents). `utils::unordered_multimap` reproduces libstdc++'s hashtable
  (prime rehash policy, bucket/list layout, equal-key placement; hash uses the
  platform `char` signedness like C++) and is tested against fixtures
  generated with libstdc++ (`test/fixtures/unordered_multimap`).
- **Parser.** Flex/bison are not used. The scanner is a hand-written engine
  that executes the transcribed flex rules (start conditions, longest match,
  `yyless`, include stack). The parser runs bison's LALR(1) algorithm
  (`lalr1.cc`) with the grammar's semantic actions written by hand; its
  tables are the ones bison computed for `seclang-parser.yy` (copied from the
  generated C++ parser) so that syntax-error locations and "expecting ..."
  lists are identical. Regenerating them after a grammar change requires
  running bison on the `.yy` and copying the tables again.
- **Optional dependencies** are cargo features mirroring the C++ `WITH_*`
  options (see README).

## Dependencies

| crate / library | replaces | why |
|---|---|---|
| `pcre2-sys` | PCRE2 (same library) | used through the C API so options, JIT fallback, match limits and error codes match exactly |
| `libinjection` (vendored, pure Rust) | libinjection (C) | pure-Rust detectors (SQLi follows libinjection's fingerprinting) |
| `md-5`, `sha1` | mbedtls md5/sha1 | standard RustCrypto digests |
| `mlua` (Lua 5.4, vendored) | liblua | Lua engine (`SecRuleScript`, `exec`, `@inspectFile`) |
| `maxminddb` | libmaxminddb | `@geoLookup` |
| `lmdb-master-sys` | liblmdb | persistent collections |
| `curl` | libcurl | remote rules, HTTPS audit log |
| system libxml2, libfuzzy | same | thin `extern "C"` bindings in the modules that use them |
| `libc`, `bstr` | — | POSIX calls; byte-string helpers |
| `jiff` | libc `localtime_r`/`strftime` | local time zone and timestamp formatting (C-locale output) |
| `aho-corasick` (optional) | — | `pm-aho-corasick` feature: alternative `@pm` matcher (off by default) |
| `prefix-trie`, `ipnet` (optional) | — | `ipmatch-prefix-trie` feature: alternative `@ipMatch` network set (off by default) |
| `rand` | `<random>`, `rand()`/`srand()` | transaction id suffix, audit log boundaries |
| — | yajl | `src/utils/json.rs` (yajl-compatible event parser, tree and generator) |

`unsafe` is confined to FFI (PCRE2, libxml2, LMDB, libfuzzy, libc calls) and
to the `extern "C"` API; every block carries a `SAFETY` comment.

## Intentional deviations from C++

- **Debug log text**: messages are `String`, so request bytes that are not
  valid UTF-8 appear as U+FFFD in the debug log (C++ writes the raw bytes).
  Error/audit logs and all matching are byte-exact.
- **`@detectXSS`** uses the vendored libinjection crate's XSS detector, which is not
  libinjection's algorithm. It agrees with C++ on every unit and regression
  case and on the CRS differential corpus, but may differ on other inputs.
  libinjection's "parser error" result never occurs (only via the test hooks).
- **C++ undefined behaviour / crashes** were given defined behaviour instead
  of being reproduced: reads past buffers in the scanner, `unique_id` and the
  LMDB prefix compare; operators called without a transaction; a leaked XML
  parser context and file descriptor. The scanner's process-global state that
  leaks between separate parses after a failed `SecRuleUpdateTarget*` is not
  reproduced.
- **libxml2 validation callbacks** use libxml2's structured error handler
  (C variadic callbacks cannot be written in stable Rust); messages and counts
  were checked to be the same.
- **Lua**: an error raised by a bad `m.*` call in tail position lacks the
  `file:line:` prefix.
- **`pm-aho-corasick` feature** (off by default): `@pm` and its file
  variants use a standard Aho-Corasick automaton instead of ACMP, which
  fixes ACMP's missed matches, its reports of phrases that are not patterns
  (and NUL truncation), and its platform-dependent handling of pattern
  bytes >= 0x80. All regression and unit cases pass either way, and on the
  CRS v4.8.0 regression suite (go-ftw, nginx) the alerts are the same as
  with ACMP. Without the
  feature the C++ behaviour is kept (the ACMP port agrees with C++
  `acmp_process_quick` on 200k random cases).
- **`ipmatch-prefix-trie` feature** (off by default): `@ipMatch` and its
  file variants keep their networks in prefix tries instead of the crit-bit
  tree of `msc_tree`. The tree's quirks (netmask arrays reset on insert, only
  the first netmask of a node applied) make it miss addresses of a listed
  network when overlapping networks are listed with it, in C++ as in the
  port; with the feature an address matches whenever any listed network
  contains it. Entry parsing (`TreeAddIP`: `atoi` CIDRs, rejected `/0` and
  explicit IPv6 `/128`, platform `inet_pton`) is shared, so the same lists
  load or fail. Compared with C++ v3.0.15 through the C API on 300 random
  lists (15,600 lookups): without the feature the results are identical;
  with it the only differences are 142 extra matches, each inside a listed
  network. All regression and unit cases pass either way.
- **Time formatting** (audit/error log timestamps, the JSON `time_stamp`,
  parallel audit log and upload directory names) always uses the C locale's
  formats and English names. C++'s `strftime` follows the process `LC_TIME`
  locale, so the output only differs if the embedding application calls
  `setlocale` (nginx does not). The local zone is read from `TZ` or
  `/etc/localtime` as with libc; the output was checked to be identical to
  glibc's across 1970–2040 in several zones.
- `xmlCleanupParser()` is not called when a `ModSecurity` instance is
  dropped (unsafe with several instances).

Faithfully *kept* C++ quirks are documented at their site (e.g.
`SecRuleRemoveById` compares range bounds as strings, LMDB
`resolveSingleMatch` uses an unpositioned cursor, setvar/`stoi` semantics).

## Verification

- **Regression suite** (`test/test-cases/regression`, 801 cases): 788 pass,
  13 skipped — identical to the C++ reference build; the skipped cases are the
  same (legacy GeoIP and `regex-dollar-endonly` builds).
- **Unit suite** (secrules-language-tests): 4336 cases, the same 11 failures
  as C++ (all `phpArgsNames.json`, a transformation libmodsecurity does not
  have), 5 skipped (legacy GeoIP).
- **Differential testing** against the C++ library built from the same
  source with all optional dependencies:
  - `test/differential/run.sh`: one C program using only the C API, linked
    once against each library, runs 60 requests (benign traffic, SQLi, XSS,
    LFI, RCE, Log4Shell, SSRF, multipart/JSON/XML bodies, protocol anomalies)
    through OWASP CRS v4.8.0 at paranoia level 4: interventions, matched rule
    ids and error-log lines are identical, and the 582,672-line level-9 debug
    logs are identical up to the UTF-8 rendering noted above.
  - `test/crs/run.sh`: the OWASP CRS v4.8.0 regression suite (go-ftw 1.0.3,
    CRS's `nginx-overrides.yaml`, the configuration of CRS's own
    `modsec3-nginx` CI service) through nginx 1.28.0 and the unchanged
    ModSecurity-nginx C connector: 3876/3876 pass with this library, as with
    the C++ one. The ModSecurity alerts of the two full runs (27,230 lines)
    are identical except for one `@detectXSS` verdict (an argument name
    `pay=div style="` flagged by C libinjection, not by the Rust detector;
    the CRS test passes either way). The same suite also passes through the
    Rust port of the connector (`connectors/nginx`).
  - During the port: all 36 transformations on ~836k random inputs (output and
    "changed" flag), ~20k generated operator cases, the parser on all
    regression rule sets, CRS and ~19k mutated configurations (acceptance,
    error text and a dump of the built rules), audit log output (serial,
    parallel, JSON), LMDB behaviour, Lua callbacks, and the body processors on
    the regression requests.
- `cargo test`, `cargo clippy --all-targets` (default, no-default-features,
  `regex-dollar-endonly`) and `cargo fmt --check` are clean.

## Known gaps

- Legacy GeoIP (libGeoIP, `WITH_GEOIP`) is not supported — only MaxMind, as in
  the reference build used for comparison.
- The C++ class API is not available to C++ connectors; they must use the C
  API (which is complete: every `msc_*` function is exported, and the shared
  library has the C++ library's SONAME, `libmodsecurity.so.3`).
