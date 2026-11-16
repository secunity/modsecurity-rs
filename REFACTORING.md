This phase separates the Rust design from the original C++ class layout.
The compatibility target is the existing engine's inputs, configuration,
diagnostics, persistence format and C API. It does not reinterpret legacy
quirks as bugs to fix during a refactor.

The first pass identified these concrete changes, in implementation order:

| Component | Previous representation | Rust representation and benefit |
|---|---|---|
| Collection records | `has_value`, `has_expiry_time`, an always-present byte vector and an optional timestamp; an in-place decoder with `invalid`/`done` flags | Independent `Option` fields distinguish absent and empty values. A pure decoder uses slices and early returns, eliminating stale state and duplicated presence flags. |
| LMDB traversal | Manual cursor close and a raw-value helper with an unconstrained output lifetime | A cursor guard borrows its transaction and closes on drop, including unwinding. Returned slices borrow the cursor until its next step. Raw-value conversion also borrows the transaction. Only the two supported forward traversal operations are expressible. |
| `setvar` | An operation tag plus a separate optional predicate, allowing missing or irrelevant operands | `Set`, `Add` and `Subtract` own their operands; `SetToOne` and `Unset` carry none. The parser constructs valid operations directly. |
| Phase storage | A `Rules` class wrapping a public vector, with `insert`, `size` and `at` forwarding methods | Phase storage owns vectors and exposes slices. Duplicate checking, ordered merging and dumping stay together in `rules_set_phases.rs`; the redundant `rules.rs` module is removed. |
| Runtime strings | A publicly mutable macro flag alongside a vector of literal/variable holders | A private literal/interpolated enum determines macro presence. Adjacent literal fragments are joined while building the string, so plain text can be borrowed during evaluation. |
| Transaction collections | A boxed concrete `TX` collection despite exclusive ownership by its transaction | The transaction owns the collection directly, avoiding an allocation without changing collection behavior or synchronization. |

The C entry points and ABI are unchanged. The normal Rust embedding API
(`ModSecurity`, `RulesSet`, `Transaction`) remains the same. Low-level Rust
construction/access APIs for collection records, `SetVar` and phase storage
change with their representations; repository callers are updated together.
No dependencies or blanket lint suppressions were added.

Compatibility details covered by focused tests include:

- Persistence retains unescaped arbitrary bytes, field order, exact ten-digit
  expiry decoding, zero-expiry quirks, pre-epoch serialization and whole-input
  fallback on malformed records. Empty values differ from absent values.
- Expiry uses the same inclusive boundary and signed-second arithmetic,
  including `i32::MIN`. Updating a value retains its expiry.
- Collection iteration, duplicate resolution and deletion order remain intact.
  LMDB's single-match traversal still starts at the first database entry,
  rather than seeking to the requested key.
- `setvar` keeps prefix integer parsing, invalid/out-of-range operands as zero,
  wrapping arithmetic, operand/name expansion order and existing log text.
- Merges check a whole phase before appending it. On duplicates, earlier
  phases remain appended; later phases do not. Only operator-rule IDs are
  checked, and rules remain shared with the source set.
- Macro expansion retains arbitrary bytes, first-value selection, missing
  values and the restriction that only operator rules reach `RULE` macros.

Baseline checks passed with default and minimal features. Default library
tests initially had 179 passes and two ignored diagnostic helpers. The suite
wrapper deliberately accepts the same 11 upstream `phpArgsNames` failures;
these are not newly introduced failures. Formatting and strict Clippy also
passed before changes.

Verification includes default/minimal tests, tests with both opt-in matcher
features, strict Clippy, and the normally ignored parser-error suite run in
isolation. A temporary differential decoder harness compared 1,901,526
generated inputs against the original decoder, including all single-byte
substitutions of representative records; value presence, expiry presence,
values and serialized bytes matched. The existing C-API differential harness
also compared the saved pre-refactor release library with the refactored
library: all 60 CRS requests matched with debug logging on and off, and all
582,671 debug-log lines matched byte-for-byte. This checks the refactor
against its Rust baseline, not a newly built C++ reference.

Performance was measured against the release library from commit `562e655`,
using `test/benchmark/bench_capi.c`, the existing CRS configuration/corpus,
Rust 1.98.1 on aarch64, and CPU 3 affinity. Five repetitions alternated the
old and new libraries (reversing which ran first on alternate repetitions).
The scenarios used 10,000 upstream transactions, 50 PL1 corpus iterations
and 30 PL4 corpus iterations per run. Median transactions per second:

| Scenario | Before | After | Change |
|---|---:|---:|---:|
| Upstream request | 3,933.7 | 3,831.7 | -2.6% |
| CRS corpus, PL1 | 3,298.7 | 3,518.9 | +6.7% |
| CRS corpus, PL4 | 2,143.9 | 2,129.0 | -0.7% |

These short, noisy runs show no large regression; they do not establish a
general speedup or measure persistent-collection-heavy workloads.

Checks used:

```sh
cargo build --release --lib
cargo test
cargo test --no-default-features
cargo test --features pm-aho-corasick,ipmatch-prefix-trie
cargo test --lib regression_parser_errors -- --ignored
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo clippy --no-default-features --all-targets -- -D warnings
cargo clippy --all-targets --features pm-aho-corasick,ipmatch-prefix-trie -- -D warnings
```

Some C++-derived patterns are retained deliberately:

- `Arc<Rule>` supports sharing across merged rule sets; `VariableValue` uses
  copy-on-write sharing to avoid repeatedly copying request data during rule
  evaluation. Boxed macro variables keep literal fragments small.
- Action/operator traits and collection/debug-log interfaces support runtime
  selection and extension. Converting all of them to large enums would not
  provide a demonstrated benefit.
- The compatibility multimap reproduces observable iteration order. Native
  `HashMap` iteration is not a substitute. The default ACMP/IP-tree algorithms
  keep their documented quirks; their opt-in alternatives remain opt-in.
- The shared-file registry and audit-writer lifecycle retain their by-name
  reopen/failure semantics. (Since replaced by owned handles, see "Owned
  state instead of process globals".)
- Remaining unsafe code is concentrated in the C ABI, external libraries and
  platform compatibility functions. The touched LMDB operations document
  handle validity, ownership and lifetime requirements. PCRE2 flags/errors,
  C allocation conventions, numeric formatting and platform parsing were not
  replaced with superficially similar APIs.

The nginx workspace member requires a separately configured nginx source/build
tree and is excluded from the default Cargo checks. This phase does not change
connector code. The CRS comparison and performance checks exercise the library
through its C API, rather than through a running nginx deployment.

The second pass starts from `7d3d2c4` and changes collection ownership across
actions, operators, variable resolution and Lua callbacks. Its baseline had
190 passing library tests and the same two ignored diagnostic helpers; the
full default suites, strict Clippy and release build passed before changes.

| Inspected issue | Change and practical benefit |
|---|---|
| TX reused a shared persistent backend, including an `RwLock`, expiry records and write-through-`&self` methods | `TransactionVariables` is owned by its transaction. Reads return borrowed byte slices; writes require `&mut` and accept owned buffers. `setvar` and Lua transfer their computed values without another copy. SecLang already rejects TX expiry, so the native TX type does not carry expiry machinery. |
| Five backend pointers and five independent selected keys were paired manually in several callers | `CollectionBinding` pairs a private backend reference with its transaction's selected key. The `Persistent` enum belongs to the collection domain and selects a binding. The binding owns compartment construction; the backend trait no longer duplicates every operation with a `_c` compartment overload. |
| Dynamic variable name, store and delete hooks independently repeated inheritance-style type checks | `Variable::write_target` returns one explicit target carrying its name expression and destination. Ordinary targets cannot perform writes. Persistent deletion retains the SESSION/IP-compartment exception in one place. |
| Lua downgraded the mutable transaction to a shared reference and relied on the backend's interior mutability for writes | Scoped callbacks use a temporary `RefCell<&mut Transaction>`. Native reads/writes borrow only for their duration; Lua allocations, conversions and calls run without a transaction borrow. This keeps foreign callback coordination at the boundary, while native engine code uses ordinary ownership. |
| Collection-selection actions copied an expanded key and kept string tags to rediscover the collection later | `initcol` stores its validated enum. Selection actions move the expanded key into the binding after updating the anchored variables that also need it. |

The normal embedding entry points and C ABI remain unchanged. The low-level
Rust collection API deliberately changes: `t.collections.tx` provides
`get`, `set` and `remove`; persistent selections use fields such as
`t.collections.ip.key` and binding methods. The old TX backend/expiry methods,
dynamic write hooks and `_c` trait overloads are removed rather than retained
as a second mutation interface. All repository callers are updated.

The compatibility container remains in TX because its ordering is observable.
A regression test compares the new TX implementation against the previous
in-memory backend through more than 1,400 keys, rehashing, case aliases,
binary keys, updates, deletions, exclusions and regex selection. Another
checks empty values, empty keys and original key spelling. Existing tests
continue to cover collection compartments, case rules, expiry rejection,
SESSION deletion and arithmetic/macro behavior. A Lua regression test forces
garbage-collection finalizers to re-enter `m.getvar` and `m.setvar` while
another callback produces Lua values, then verifies subsequent access after
a caught Lua argument error.

The default library suite now has 193 passing tests. Default, minimal-feature
and opt-in matcher test suites and strict Clippy checks pass, along with
formatting and the release build. The known 11 upstream unit-suite failures
remain exactly as before. Comparing the saved `7d3d2c4` release library with
this pass through the C API gives identical output for all 60 CRS requests
with debug logging enabled and disabled; all 582,671 debug-log lines match
byte-for-byte.

Release benchmarks compare this pass with the saved `7d3d2c4` library using
the same C API harness and rule files. Five runs per workload alternate the
before/after order and pin execution to CPU 3. Median throughput was:

| Workload | Before (transactions/s) | After (transactions/s) | Change |
|---|---:|---:|---:|
| Upstream request, PL1 | 4,137.1 | 4,239.9 | +2.48% |
| 60-request corpus, PL1 | 3,573.8 | 3,660.3 | +2.42% |
| 60-request corpus, PL4 | 2,226.4 | 2,272.1 | +2.05% |

Each run processes 10,000 upstream requests, 3,000 PL1 corpus requests or
1,800 PL4 corpus requests. These local measurements show no material
throughput regression in the exercised paths; they are not a guarantee for
other deployments or workloads.

This pass does not redesign the main transaction pipeline, the complete
action-construction hierarchy or shared-file/audit-writer lifecycles. Shared
persistent backends retain synchronization, and existing external-library
unsafe boundaries remain. The new TX store and binding code use no unsafe
code or interior mutability; the scoped Lua borrow cell is the deliberate
exception at the callback boundary.

The third pass starts from `7f9a09b` and narrows ownership in request argument
and JSON parsing. Its default baseline had 193 passing library tests and two
ignored diagnostic helpers; full tests and strict Clippy passed before edits.

| Inspected issue | Change and practical benefit |
|---|---|
| JSON retained a yajl-style `process_chunk`/`complete` interface, copying the already buffered request into another buffer | `Json::parse` borrows the body and calls an argument sink directly. There is no second input buffer or intermediate list of parsed arguments. Cancellation still stops at the same scalar and preserves earlier arguments. |
| JSON callbacks borrowed the entire transaction; the transaction temporarily removed an `Option<Box<Json>>` to call them | `ArgumentWriter` borrows variable state plus logging/configuration context. The transaction can independently borrow its body and plain owned `Json` state. There is no temporary missing parser or allocation for the parser object. |
| JSON stored both a container stack and a signed depth counter, comparing depth against a floating-point limit | The stack length is the depth, and the configured limit remains an integer. The existing sticky depth-error flag and partial path state are retained across repeated processing. |
| Form parsing first copied every input segment into an owned vector, then copied keys and values for decoding | A borrowed `split_inclusive` traversal retains `std::getline` empty/trailing-separator semantics. Only the key and value being decoded need owned buffers. |
| Request/response variable population cloned whole bodies before copying them into anchored variables | Independent field borrows remove those temporary copies. The body snapshots required by rule variables are still owned. XML and multipart retain their existing parser paths and their temporary input copy. |

`Transaction::add_argument` and `extract_arguments` retain their existing
signatures and return behavior. The low-level `Transaction::json` field is now
a `Json` value, and its parser uses the borrowed-input API. Normal embedding
entry points and the C ABI are unchanged. No dependencies or unsafe code were
added.

Four regression tests cover repeated JSON processing after errors, empty-body
error handling, sticky depth errors, binary argument values, decoded-key
offsets, custom separators, empty arguments, origin case sensitivity and
continued form decoding after an argument limit. The repeated-processing
tests were also run against the original implementation before refactoring.
Error text, `ARGS_COMBINED_SIZE` floating-point formatting, insertion order
and debug logging are deliberately preserved.

Default, minimal-feature and opt-in matcher suites pass, with 197, 181 and
198 library tests respectively (two diagnostic helpers remain ignored in each).
Strict Clippy passes for all three configurations. The known 11 upstream
unit-suite failures remain unchanged. The release C API comparison matches
all 60 CRS requests with logging enabled and disabled and all 582,671 debug
lines byte-for-byte.

A separate C API comparison exercises 27 JSON/form requests under seven
configurations: normal parsing, an argument limit, depth limits of zero and
two, a body-size limit, disabled body access and a custom separator. All 189
request outputs and 12,718 debug lines match the saved baseline byte-for-byte,
including malformed input, duplicate/empty keys, raw numeric spelling and
invalid UTF-8.

Five alternating, CPU-3-pinned release benchmark runs compare this pass with
`7f9a09b`. The three CRS workloads use the same harness and iteration counts
as the previous pass. Two additional workloads process 500 requests per run,
each with a single 512 KiB value in a JSON object or URL-encoded form. Those
use body access enabled, 1 MiB body limits and one JSON-selection rule, without
CRS or debug logging, to exercise parsing and copying directly.

| Workload | Before (transactions/s) | After (transactions/s) | Change |
|---|---:|---:|---:|
| Upstream request, PL1 | 4,135.9 | 4,246.6 | +2.68% |
| 60-request corpus, PL1 | 3,672.0 | 3,681.3 | +0.25% |
| 60-request corpus, PL4 | 2,270.1 | 2,286.2 | +0.71% |
| 512 KiB JSON value | 619.2 | 632.9 | +2.21% |
| 512 KiB form value | 1,044.2 | 1,116.4 | +6.91% |

These local median throughput measurements show no material regression in
the exercised paths. Formatting, whitespace checks and the release build
also pass. The broader phase orchestrator, XML/multipart parser ownership,
action construction and shared-file/logging lifecycles remain unchanged;
this pass introduces no new unsafe code or suppression attributes.

The content-offset renderer also no longer carries private emulations of
`std::stoi` and `std::string::substr`. Its offset tokens come from decimal
regex captures, so standard `parse::<i32>()` supplies the required range
checking without a general prefix parser. Checked offsets and borrowed byte
slices replace substring allocation. The public renderer retains its error
text and error precedence, end-of-content truncation, NUL termination and
existing output quirks. Two regression tests covering integer boundaries,
leading zeros, empty ranges and binary content passed before and after the
change. Full default tests (199 library tests), strict Clippy and formatting
pass; the known upstream failures and ignored diagnostics are unchanged.

## SecLang front end: a `pest` grammar

The SecLang parser was a port of the C++ flex scanner and bison parser: a
table-driven LALR(1) automaton (`seclang_parser.rs`, ~3,500 lines) and a
flex engine with 35 start conditions (`seclang_scanner.rs`, ~2,000 lines).
It was hard to change and carried scanner bugs (e.g. upstream PR 3753). It
is replaced by:

- `src/parser/seclang.pest`: the grammar of directives, variables, operators
  and actions (~230 lines).
- `src/parser/syntax.rs`: reads one statement at a time into a small syntax
  tree that borrows the configuration text.
- `src/parser/build.rs`: applies each statement (names, values, rules,
  `Include`) through the same constructors as before. Directive values are
  read as the C++ scanner reads them (first separator, `parserSanitizer`,
  longest match between its rules), so properties and rules are the same.

The replacement was first added behind a `pest-parser` feature (commit
4a83876), compared with the old parser as below, and then made the only
parser (the owner accepted the load-time cost). The comparison harness was
removed with the old parser; `src/parser/tests.rs` keeps the configuration
corpus and checks that both ways of reading a file build the same.

Compatibility:

- What a configuration builds is identical on real configurations, compared
  by `src/parser/equivalence.rs` (rules of every phase, all properties,
  default actions, exceptions): OWASP CRS 4.8 (each file and the whole set
  through `Include`), `modsecurity.conf-recommended`, the rules of every
  regression test, the downloaded regression rule file and the `.conf` files
  of `test/test-cases/data` — 831 configurations.
- C++ quirks kept by this change (fixed afterwards, each in its own commit;
  see `MIGRATION.md`):
  rule line numbers as the C++ scanner counts them (fixed since: they are
  the line of the rule's keyword);
  a `%` right after a macro is dropped (kept on purpose: `%{VAR}%` is a
  form the regression tests use; a lone `%` elsewhere was fixed since); the escaped quote of PR 3753 keeps
  its backslash (fixed since for operators); an action list may miss its closing quote at the end of a
  line (fixed since); a directive on the line right after a rule without actions is an
  error (fixed since); a whole collection followed by a plain regular expression
  (`SecRule TX "foo"`) is an error (fixed since); an unknown `@operator` is a regular
  expression (fixed since); `phase:'request'` builds an `allow` action (fixed since).
- Syntax error messages and their line/column differ (approved: not part of
  the contract). The regression runner compares only that a syntax error
  happens, and the other errors without their position.
- The whole regression suite passes; the differential
  test against C++ (60 requests, CRS PL4, 582,671 debug log lines, and the
  pass without the debug log) is identical; the CRS suite through nginx
  passes (3,876/3,876).
- A file is read at once; after a syntax error it is read again statement
  by statement, so the statements before the error are applied first (as
  in C++). Both reads build the same on every real configuration (tested).
- Performance (7 interleaved runs against the flex parser, CRS with
  `modsecurity.conf-recommended`): transactions/s, p99 and RSS unchanged
  (PL1 3,560 → 3,555 tx/s median, PL4 2,199 → 2,214; RSS −1 MB); rule load
  time PL1 43.9 → 48.1 ms best (44.4 → 51.7 median), PL4 44.1 → 48.4 best
  (44.3 → 49.2 median), i.e. about +4 to +7 ms per CRS load. The text
  classes are written so that pest skips plain runs with `memchr`
  (`(!"x" ~ ANY)*` inside atomic rules), pest is built without its stack
  guard, and ASCII configurations are parsed without copying.
- On 1,004,685 single-character mutations of 1,000 configuration lines,
  the new parser never accepts what the old one rejects. 10,169 mutations
  are rejected by the new parser only: junk at token boundaries that the
  flex scanner silently skips (its default rule echoes unmatched bytes to
  stdout; that output is gone) or misreads, e.g. `SecRule% ARGS`, `"@lt 3""`, `"@lt' 3"`,
  `!"@rx a"`. 4 build differently: `setvar:tx.a=\%{x}`, where flex makes
  `=\%{x}` part of the key.

## Unsafe code only at the boundaries

`unsafe` is confined to the modules where Rust meets C, and the compiler
enforces it: the crate has `#![deny(unsafe_code)]`, and only these modules
allow it (where they are declared):

| Module | Boundary |
|---|---|
| `capi` | the C API (`msc_*`, `ModSecurityIntervention`); since moved to the `modsecurity-capi` crate |
| `utils::regex` | PCRE2 |
| `utils::libxml2` | libxml2 |
| `utils::system` | libc (`wordexp`, `mkstemp`, `setenv`, time, `strerror`) |
| `utils::geo_lookup` | MaxMind DB |
| `utils::https_client` | curl |
| `collection::backend::lmdb` | LMDB |
| `engine::lua` | Lua |
| `operators::fuzzy_hash` | ssdeep |

(plus three tests that compare with C functions).
These modules have since become the `modsecurity-capi` and
`modsecurity-native` crates (see "Workspace" below).

Steps:
- The C API moved from `c_api` submodules of `transaction.rs`,
  `rules_set.rs` and `modsecurity.rs`, and the C half of `intervention.rs`,
  to `src/capi/`. The exported symbols are unchanged (39 `msc_*`, compared
  with `nm`).
- `@verifyCC` used a private PCRE2 binding: it uses `utils::regex`
  (`Regex::find_at`). `id:` validation used `snprintf("%.40g")`: `format_g`
  does it in safe Rust (compared with `snprintf` on 60,000 doubles).
  `setenv` and `mkstemp` moved to `utils::system`.
- libxml2: the FFI moved from the request body processor to
  `utils::libxml2`, with a safe API (`PushParser`, `SaxParser` +
  `SaxHandler`, `Document::{xpath, validate_dtd, validate_schema}`, `Dtd`)
  that the body processor, the `XML` variable and the validation operators
  use.

No behavior change (regression and unit suites, differential test, CRS);
`Transaction` stays `Send`, `ModSecurity` and `RulesSet` `Send + Sync`
(tested).

## Owned state instead of process globals

C++ keeps some configuration state in process-wide singletons. The Rust
code gives it to the object it belongs to.

- **Log files.** The debug log and the audit log writers opened files
  through a registry by name, and closed them by name: a writer released
  whatever its configuration named at the time it was dropped, which after
  a merge was the new configuration's files (fixed first, see MIGRATION.md).
  `SharedFile::open` now returns an `Arc<SharedFile>` that the log keeps
  (`DefaultDebugLog::file`, the audit `Writer` enum); the file is closed with
  its last handle. The registry remains, with weak entries, so that the logs
  of one process that name the same path still share one descriptor and one
  mutex (the `fcntl` lock does not exclude threads). No behavior change.
- **GeoIP database.** `GeoLookup::instance()` was replaced by `GeoDb`, owned
  by the rule set (`RulesSetProperties::geo_db`, an `Arc` shared by the rule
  sets it is merged into). The C API creates rule sets without a
  `ModSecurity`, so the rule set, not the engine, is the owner. This changes
  which database a rule set without `SecGeoLookupDb` uses (MIGRATION.md). The
  database is read into memory, as before; one per `SecGeoLookupDb` loaded,
  where C++ replaced (and leaked) a memory map. Memory-mapping it would need
  `maxminddb`'s `mmap` feature.
- **`msc_who_am_i`** returned a string cached in a process-wide static (the
  first instance's). Each `ModSecurity` now keeps its own C string, which
  lives as long as the instance, as the C++ API documents. Same text.

Kept as process state, on purpose:
- The LMDB environment of the persistent collections: LMDB forbids opening
  one environment twice in a process, and its path is fixed
  (`./modsec-shared-collections`).
- The `SharedFile` registry (weak entries, see above), the per-machine
  `UNIQUE_ID`, and the per-thread PCRE2 match scratch and libinjection test
  hooks, which are caches or test aids rather than configuration.

## Documentation describes the Rust code

The module headers no longer start with "Port of `file.cc`" (161 files),
and doc comments that only named the C++ counterpart (`` /// `resolveFirst` ``,
`` /// `luhnVerify`: ... ``) now say what the item does (about 400). Names
that mean something to users stay: SecLang directives, actions, operators
and variables, `msc_*`, and library functions (`luaL_checkstring`,
`getaddrinfo`); so do the notes on how the code relates to C++ behavior
(quirks kept, "as in C++"), since C++ remains the behavioral reference.
Comments only: checked by comparing the code with comments stripped, and
`cargo doc` gives the same warnings as before (all new links resolve).

## A small public Rust API

The crate exposed nearly every module (`actions`, `operators`, `variables`,
`utils`, ...) and the internals of its main types (133 public fields on
`Transaction`). The API is now the types re-exported at the crate root:

- `ModSecurity`, `RulesSet`, `Transaction`, `Intervention`;
- the server log callback: `ModSecLogCb`, `ServerLogEntry`, `RuleMessage`
  (with the `*_LOG_PROPERTY` and `*_LOG_MESSAGE_INFO` flags);
- the `DebugLog` trait, for `RulesSet::with_debug_log`;
- the version constants, and `ModSecurity::process_content_offset`;
- `LoadError`, the error of `RulesSet::load*` and `RulesSet::merge`
  (a `std::error::Error` holding the parser errors the C API reports).

Everything else is `pub(crate)`: the modules, the fields of the API types
and their engine-internal methods (rule evaluation, merging a parser
driver, audit log rendering, ...). The C API (`capi`) is unchanged: same
39 exported `msc_*` symbols. The test utilities of the repository reach the
internals they drive (operators, transformations, the JSON tree parser) via
`modsecurity::internal`, which is `#[doc(hidden)]` and not an API.

Making the modules private surfaced code nothing used, removed:
`Collection::{name, update_first, resolve_single_match}` (and the LMDB
`MDB_NEXT_DUP` walk the last one needed), the regex resolution helpers
of the anchored variables, unused constants (`ACMP_FLAG_*`, `OVECCOUNT`,
`IPV4_LEN`, ...), and a few unused wrappers. Helpers only the unit tests
used are `#[cfg(test)]`; code only an optional feature uses (Lua, LMDB,
libxml2, curl) or that an opt-in feature replaces (ACMP, the crit-bit IP
tree) says so where it is declared.

## Embedding in Rust HTTP servers

Two opt-in features build on the API above, without changing the default
build:

- `http`: `Transaction::process_request_head` and `process_response_head`
  take `http::Request`/`http::Response` (the request target, method,
  version and headers, then the phase), and `Intervention::to_response`
  builds the response the nginx connector would send (a redirect to the
  URL, or an empty response with the status). For HTTP/2 and 3 the target
  is the path and query, with a `Host` header from the authority, as
  nginx passes them. `Transaction::process_connection_addrs` (always
  available) takes `SocketAddr`s.
- `tower`: `middleware::ModSecurityLayer`, a tower `Layer` that runs the
  phases in the nginx connector's order around an inner service. The
  request body is read completely and handed on in the caller's body type
  (any body that converts from `Bytes`); the response body is buffered
  only when the rules inspect it. Errors are the inner service's (body
  read failures become 400/502 responses), so it fits axum, which needs
  infallible services.

`examples/axum` (a workspace member outside `default-members`) serves an
application behind the layer and tests it over real sockets.

## Workspace: engine, native wrappers, C API

The single crate is split along its two boundaries with C (approved by
the owner):

| Crate | Path | Contents |
|---|---|---|
| `modsecurity` | `.` | the engine and its Rust API (rlib); `#![forbid(unsafe_code)]` |
| `modsecurity-native` | `crates/modsecurity-native` | the C libraries behind safe APIs: PCRE2, libxml2, LMDB, ssdeep, Lua, libc calls |
| `modsecurity-transformations` | `crates/modsecurity-transformations` | the `t:` transformations as pure functions, and the decoders shared with the engine |
| `modsecurity-seclang` | `crates/modsecurity-seclang` | the SecLang grammar (`seclang.pest`) and its syntax tree |
| `modsecurity-compat` | `crates/modsecurity-compat` | what reproduces C++ behavior: ACMP, the crit-bit IP tree, the libstdc++-ordered multimap, the yajl-compatible JSON |
| `modsecurity-operators` | `crates/modsecurity-operators` | the 33 operators that only match, against the `Context` and `Resources` traits |
| `modsecurity-body` | `crates/modsecurity-body` | the request body processors (multipart, JSON, XML), against context traits |
| `modsecurity-capi` | `crates/modsecurity-capi` | the `msc_*` C API: `libmodsecurity.so.3` and `libmodsecurity.a` |

The engine stays at the root, so the test suites, the test data and the
scripts keep their paths. The C library is built with `cargo build -p
modsecurity-capi` (part of the default members); its library target is
still named `modsecurity`, so the files keep their names, and its
features forward to the engine's. The exported symbols, the SONAME and
the linked libraries are identical to the single crate's (compared with
`nm -D` and `readelf -d`). The C API uses only the engine's public API;
it needed two accessors, `Transaction::rule_messages` and
`RuleMessage::rule_id` (for `msc_get_rules_messages_*`), and
`ModSecurity::who_am_i_c` became public.

`modsecurity-native` holds all the engine's `unsafe` code, so the engine
crate forbids it (`forbid`, which no module can lift):

- moved as they were: the PCRE2 wrapper (`regex`) and the libxml2 one
  (`libxml2`); the engine re-exports them as `utils::regex` and
  `utils::libxml2`;
- `posix`: `setenv`, `mkstemp`, `wordexp` and `gai_strerror`, taken out
  of `utils::system` and the GeoIP lookup;
- `lmdb`: the shared environment, transactions (`get`/`put`/`del`/
  `commit`, aborted on drop) and cursors, with borrows that tie returned
  values to their transaction; the collection backend uses them;
- `ssdeep` (`hash`, `compare`) and `lua::new_state` (the one `unsafe`
  `mlua` constructor);
- `testing` (a feature, enabled by the engine's dev-dependency): the C
  functions tests compare with (`inet_pton`, `snprintf`, `strftime`,
  `strerror`).

The native crate links libxml2 and libfuzzy (its build script); the
engine's features enable its features. The C library's symbols, SONAME
and NEEDED entries are again identical. The library benchmark,
interleaved against the parent commit (5 rounds, and 10 for `upstream`),
shows no difference beyond noise (best throughput `upstream` 4182 → 4175
tx/s, `corpus_pl1` 3613 → 3569, `corpus_pl4` 2252 → 2249; medians
+3.3%, +2.7%, +1.1%), so the PCRE2 calls crossing a crate boundary cost
nothing measurable.

### The transformations crate

`modsecurity-transformations` holds the 38 transformations as functions on
bytes: `Transformation` (an enum) with `apply(value, &Context)`. Nothing in
it knows rules or transactions; the one outside input, the unicode map of
`t:urlDecodeUni`, comes in the `Context`. The engine's action
(`actions::transformation::Transformation`: the name as written plus the
kind) builds the context from the transaction.

- The two name lookups live together: `from_name` (what a rule writes
  after `t:`, any case; the parser's table, which moved here) and
  `from_name_prefix` (the C++ factory's case-sensitive prefix match, still
  used by Lua and `process_content_offset`). They differ on purpose
  (`cmdLine` vs `cmd_line`, prefixes, unknown names), so they stay two.
- The decoders the engine uses elsewhere moved with them and are
  re-exported under their old paths: `base64`, `url` (`utils::decode`) and
  the byte helpers `chars` (part of `utils::string`).
- `[profile.release] lto = "thin"`: without it the split measured 1-2% of
  throughput (calls into the crate are not inlined); with it the build is
  at parity or ahead, and rule loading is about 6% faster. A from-scratch
  release build of the C library takes about 20 s either way.

### The SecLang syntax crate

`modsecurity-seclang` is the grammar and the syntax tree (`Statement`,
`Directive`, ...) that used to be `parser::syntax`; it depends only on
`pest`. It knows the shape of the language, not its names: the engine's
`parser::build` still decides which variables, operators and actions exist,
so the crate also suits tools that only read configurations. The engine
refers to it as `parser::syntax`.

### The compat crate, and whole-program optimization

`modsecurity-compat` holds the four modules that exist to reproduce what
the C++ library does, quirks included, and that depend on nothing else:
`acmp` (`@pm`), `msc_tree` (`@ipMatch` and its address parsing),
`unordered_multimap` (the iteration order of `ARGS` & co.) and `json`
(yajl's reader and writer). The engine re-exports them under `utils::`.
The `ipmatch-prefix-trie` feature forwards to the crate, which now owns the
`prefix-trie` and `ipnet` dependencies.

The release profile is now `lto = "fat"` with `codegen-units = 1`. Thin
LTO left this split about 1% slower (an A/A control put the noise floor at
0.5%); whole-program optimization makes crate boundaries free and is about
2% faster than before any split. A release build takes about 30 s.

## Operators see a `MatchContext`, not the transaction

`Operator::evaluate` took the transaction, the rule and the rule message.
It now takes a `MatchContext` and the input. The context offers what a
matcher needs and nothing else: the parameter expanded for the
transaction, whether the rule captures, `set_capture`, `matched`,
`offset`, the PCRE match limit and error reports, and the debug log
(`op_dbg!`). 33 of the 38 operators use only that. The five that are part
of the engine rather than matchers (`@geoLookup`, `@inspectFile`, `@rbl`,
`@validateDTD`, `@validateSchema`) reach the transaction through
`MatchContext::transaction`, which marks them. This is the step before
moving the matchers to their own crate: the context becomes that crate's
trait.

### The operators crate

`modsecurity-operators` holds the 33 operators that only match. Its
`Context` trait is what `MatchContext` offered (the engine implements it
for `MatchContext`), and `Operator::init` gets a `Resources` for the files
and URLs a parameter names (`@pmFromFile`, `@ipMatchFromFile`,
`@fuzzyHash`); the engine supplies its resource lookup and HTTPS client.
An operator's `Param` is plain data (the text without macros, and whether
it has any); the engine's `RuleOperator` keeps the macro string and the
context expands it.

The engine keeps its own `Operator` trait, which takes the `MatchContext`:
the five operators that need the transaction implement it directly
(`@geoLookup`, `@inspectFile`, `@rbl`, `@validateDTD`, `@validateSchema`),
and a `Matcher` wrapper runs the crate's operators behind it. The crate's
tests run against a recording context, without a transaction. The byte and
string helpers both sides use (`find`, `limit_to`, `to_hex_if_needed`,
`split`, the hex digits) are in `modsecurity_compat::chars`.

### The body processors crate

`modsecurity-body` holds the three request body processors. Each reports
what it parses through a trait the transaction implements
(`transaction/body.rs`):

- `multipart::Context`: `set` / `add` for the 27 variables the parser
  reports (named by the `Flag` and `Entries` enums), the upload settings
  (`Uploads`), the name prefix of a temporary upload file, `keep_tmp_file`
  and the debug log;
- `xml::Context`: the two XML settings, `add_argument` and the debug log;
- `json`: it already took a callback for the arguments.

Their tests that run a whole transaction stayed in the engine
(`request_body_processor/tests/`). `chomp`, `lossy` and `strerror`
(`compat::errno`) moved to `modsecurity-compat`.


## `Transaction` state grouped by purpose

The 41 loose fields of `Transaction` are now five structs, one per
concern (the first step of splitting the transaction, see `PLAN.md`):

| Field | Type | Holds |
|---|---|---|
| `http` | `HttpData` | the exchange as the connector reported it: addresses and ports, host name, HTTP version, the raw and decoded URIs, the request and response bodies, `ARGS_COMBINED_SIZE`, the status code |
| `body` | `BodyProcessing` | the body type and the processor chosen, the XML and JSON processors, the multipart temporary files |
| `ctl` | `CtlOverrides` | what `ctl:` changed for this transaction: rule engine, body access, XML into `ARGS`, audit engine and parts, the five `ruleRemove*` lists |
| `eval` | `EvalState<'a>` | `skip_next`, the `SecMarker` being skipped to, `allow`, the chain being evaluated, captures, the reused buffers |
| `outcome` | `Outcome<'a>` | the rule messages, the intervention, `is_interrupted`, the highest severity |

`ms`, `rules`, `id`, the two timestamps, `vars`, `collections`,
`variable_envs` and `log_cb_data` stay on `Transaction`. `PLAN.md` put
the audit-log `ctl` settings with logging; they are in `ctl` because
`ctl:` sets them like the others. Field names are unchanged except where
the group repeats them: `eval_scratch` → `eval.scratch`,
`sec_rule_engine` → `ctl.rule_engine`, `sec_xml_parse_xml_into_args` →
`ctl.parse_xml_into_args`, `ctl_audit_engine` → `ctl.audit_engine`.

The accesses were rewritten from the compiler's errors (a script turned
each "no field `x` on type `Transaction`" into `x`'s new path), so no
statement changed place. Drop order changed only among fields whose drop
has no visible effect: the temporary files are still released, with
their debug messages, by `Transaction::drop` before any field is
dropped. The differential test is identical (582,671 debug log lines;
outputs with and without the debug log), and the C library's symbols,
SONAME and NEEDED are unchanged.

## Actions see an `ActionContext`, not the transaction

`Action::evaluate` takes one `&mut ActionContext` instead of the rule, the
transaction and the rule message (`src/actions/context.rs`; the second
step of splitting the transaction, see `PLAN.md`). The context offers what
actions do, as typed operations:

| Operations | Used by |
|---|---|
| `debug_enabled`, `debug` (the `act_dbg!` macro) | most actions |
| `expand` (macros of the action's text) | `msg`, `logdata`, `tag`, `redirect`, `setenv`, `setsid`/`setuid`/`setrsc`, `initcol`, `expirevar` |
| `set_save_message`, `set_no_audit_log`, `set_message`, `set_log_data`, `add_tag`, `set_severity` (the rule message) | `log`, `nolog`, `auditlog`, `noauditlog`, `msg`, `logdata`, `tag`, `severity` |
| `intervention_status`, `set_intervention_status`, `set_intervention_url`, `disrupt`, `reset_intervention`, `highest_severity`, `set_highest_severity` | `deny`, `drop`, `redirect`, `pass`, `status`, `severity` |
| `skip_next`, `skip_after`, `allow` | `skip`, `skipAfter`, `allow` |
| one setter per `ctl:` setting, `set_request_body_processor` / `set_request_body_type` | the 13 `ctl:` actions |
| `set_resource`, `set_session_id`, `set_user_id`, `init_collection`, `collection_key`, `expire`, `set_env` | `setrsc`, `setsid`, `setuid`, `initcol`, `expirevar`, `setenv` |

Each operation is the statements the action ran itself before, in the
same order; `disrupt` is the three statements `deny`, `drop` and
`redirect` shared (disruptive intervention, disruptive rule message, the
intervention's log line). `ctl:requestBodyProcessor=URLENCODED` keeps
setting the body *type* where JSON and XML set the processor, as in C++.

Three actions are part of the engine and reach the transaction with
`ActionContext::engine()`: `setvar` (resolves and writes any variable),
`exec` (runs Lua with the transaction) and `block` (runs the phase's
default disruptive actions in the same context). Everything else is
written against the context only, which is what lets those actions move
to a crate later (step 2 of `PLAN.md`).

The call sites were rewritten from the compiler's errors. The
differential test is identical (582,671 debug log lines; outputs with
and without the debug log), and so are the C library's symbols, SONAME
and NEEDED.
