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

Checks used (at the time; the `pm-aho-corasick` and `ipmatch-prefix-trie`
features were removed later):

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
  (with the `LogProperties` and `LogParts` flag sets);
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

## Audit log rendering in `audit_log::format`

The three renderers moved out of `transaction.rs` (third step of
splitting the transaction, see `PLAN.md`) into `src/audit_log/format.rs`,
as functions of the transaction they read:

| Was (`Transaction` method) | Now |
|---|---|
| `to_old_audit_log_format` | `format::native(t, parts, trailer, prefix)` |
| `to_old_audit_log_format_index` | `format::native_index_line(t, filename, size, md5)` |
| `to_json` | `format::json(t, parts)` |

The bodies moved statement for statement (`self` became `t`), with their
helper `cstr_prefix`. The three writers (`serial`, `parallel`, `https`)
call them; `transaction.rs` lost about 290 lines.

Before the move, the differential test gained an audit log pass (commit
"Compare the audit logs in the differential test"): Serial native with
every part, Serial JSON, and Concurrent (index and entries), compared
with C++ after normalizing dates, boundaries, storage paths and the
entry md5. It was identical before the move and is identical after; the
parent's and this build's logs are also identical to each other.

## Actions are a closed enum

`RuleAction` (`src/actions/rule_action.rs`) has one variant per action
type, 49 in all; it replaces `Box<dyn Action>` / `Arc<dyn Action>` in
rules, `SecDefaultAction` lists and `SecRuleUpdateActionById`, and the
parser enum of the same name, whose `Other(Box<dyn Action>)` held
everything without a slot of its own. A macro declares the variants and
generates the `From` conversions (the parser's `other(x)` is
`x.into()`), `Debug` (the action's own, so printed configurations are
unchanged) and the dispatch of `name`, `kind`, `is_disruptive`,
`configure` and `evaluate`, as a `match`.

The `Action` trait stays as the interface each action type implements,
without its three downcast hooks; their callers match instead:

| Hook | Now |
|---|---|
| `as_transformation` | `RuleAction::Transformation(t)` (`as_transformation()`, `is_transformation_none()` on the enum) |
| `is_block` | `matches!(a, RuleAction::Block(_))` |
| `xml_namespace` | `RuleAction::XmlNs(x)`, through `RuleWithActions::xml_namespaces`, which replaces `actions_by_name` (its only caller looked for `xmlns`) and keeps its order and its test of the name as written |

Rule evaluation order, the slots of `RuleWithActions` and every action's
behavior are unchanged. The differential test is identical (debug log,
outputs, audit logs), as are the C library's symbols, SONAME and NEEDED.

## `@rbl`, `@validateDTD` and `@validateSchema` in the operators crate

Three of the five operators left in the engine needed the transaction
for one thing each, which the operators' `Context` now offers:

| Operator | Needed | `Context` method |
|---|---|---|
| `@rbl` | `SecHttpBlKey` (the key of httpbl.org lookups) | `httpbl_key()` (empty when not set) |
| `@validateDTD`, `@validateSchema` | the document the XML body processor parsed | `xml_document()` (the document and its well-formedness flag; with the `libxml2` feature) |

They moved in two commits, as the other extractions: first the
methods on the engine's `MatchContext` and the operators rewritten
against them (`@rbl`'s logging helpers take the context instead of an
optional transaction), then the files into `modsecurity-operators`, whose
`Context` trait gained the two methods. The crate gains a `libxml2`
feature (enabled by the engine's) and the `dns-lookup` dependency
(`getaddrinfo`, as before). Their `init` finds the DTD or schema
through `Resources::find`, which the engine implements with the same
lookup as before.

`@geoLookup` (fills the `GEO` collection from the rule set's database)
and `@inspectFile` (runs Lua with the transaction) stay in the engine;
the engine's `op_dbg!` macro, now unused, is gone. The tests that need
an XML document parsed by a transaction stay in the engine and build
the operators through `operators::operator::instantiate`; `@rbl`'s test
runs against the crate's `TestContext` and now also checks the
`SecHttpBlKey` prefix.

## Collections in their own crate, on a shared-types crate

Two crates below the engine (PLAN.md step 3):

| Crate | Contents | Depends on |
|---|---|---|
| `modsecurity-types` | `VariableValue` (with `move_to_front_reversed`), `VariableOrigin`, `KeyExclusion` / `KeyExclusions` (from `variables/variable.rs`) | `modsecurity-native` (the regex exclusions) |
| `modsecurity-collections` | all of `src/collection`: the `Collection` trait, `Persistent`, `compartment_key`, the in-memory and LMDB backends (`lmdb` feature), the per-transaction bindings (`Collections`) and the `TX` variables | `modsecurity-types`, `modsecurity-native` (regex, LMDB), `modsecurity-compat` (the multimap), `libc` (LMDB errno values, with `lmdb`) |

The engine keeps its paths: `crate::variable_value`,
`crate::variable_origin` and `crate::collection` are the crates'
modules (`pub(crate) use`), and `variables::variable` re-exports the key
exclusions, so the rest of the engine did not change. The files moved as
they were, except:

- methods the engine calls became `pub` (they were `pub(crate)`), and the
  `allow(dead_code)` markers for items only the `lua` or `lmdb` builds
  used are gone (public items of a library are not dead code);
  `Persistent::from_name` is no longer behind the `lua` feature;
- `Persistent::variable` (builds the engine's `COL`, `COL:key`, ...
  targets) cannot be an inherent method of a type of another crate: it
  is `variables::persistent::variable(collection, selector)`;
- a test of the LMDB backend names its keys with the time from `std`
  rather than the engine's `utils::system::now`.

The persistent collection format (`CollectionData::serialize`) moved
unchanged. The key exclusions got their first test.

## One name table per family

PLAN.md step 4. Each family's names now live in one place; where two
lookups remain, they differ on purpose (as in C++) and sit side by side.

**Operators.** The parser's `operator_name` table became
`modsecurity_operators::seclang_operator`, next to `instantiate`: for each
name of the grammar, the name to build it by, whether it takes a
parameter, and the ones recognised but "not yet supported". The two stay
distinct, as the C++ grammar and `Operator::instantiate` are: `@pmf` is
`@pmFromFile` for the grammar but the `PmF` operator for `instantiate`,
`@noMatch` is not a SecLang operator, `@validateHash` / `@gsbLookup` /
`@rsub` are rejected by the grammar only. A crate test checks that every
operator the grammar accepts can be built.

**Variables.** `src/variables/names.rs` has the variables of the
transaction once: `SINGLE` (token, the name SecLang shows, the field,
whether SecLang and Lua know it), `SETS` (22 multi valued variables) and
`NAMES` (the three `*_NAMES` proxies). `new_variable` and Lua's lookups
by name (`string_match_resolve`, `string_match_resolve_multi`) read them
instead of three hand-written lists (the multi valued variables were
written out three times, the single ones twice). The differences of the
C++ lookups are columns of the table or stated in the code:

- Lua knows neither six `MULTIPART_*` flags nor `STATUS`; its `RESOURCE`
  is `setrsc`'s single variable, SecLang's the persistent collection;
- SecLang names `UNIQUE_ID` `UNIQUEID` and `REQBODY_PROCESSOR_ERROR_MSG`
  `PROCESSOR_ERROR_MSG` (the C++ class names);
- Lua compares `REQUEST_HEADERS_NAMES` / `RESPONSE_HEADERS_NAMES` with the
  whole name, key included (so only the keyless form is found), and its
  single-value lookup never finds the `ARGS*_NAMES` proxies (same
  comparison); `AnchoredSetVariableTranslationProxy::resolve_first`, used
  only by that unreachable branch, is gone.

Before the old lookups were deleted, a test ran both old and new on
every name of the tables and of the special variables (101 names), as
written, lower case and mixed case, with no key, `:k`, `.k`, `:x` and
`:`, for both Lua lookups (values and errors) and for `new_variable` with
the four kinds of selector (variable name and values), in a transaction
where every variable has a distinct value: identical. (A flag flipped in
the table makes it fail.) A smaller test of the differences above stays.

## Engine modules grouped (PLAN.md step 5)

The crate root had 25 files, one per C++ header. Four moves, each
rewriting paths only (no code changed; the public API and
`modsecurity::internal` are unchanged):

| Was | Now |
|---|---|
| `rule.rs`, `rule_marker`, `rule_message`, `rule_script`, `rule_unconditional`, `rule_with_actions`, `rule_with_operator` | `rule/` (`mod`, `marker`, `message`, `script`, `unconditional`, `with_actions`, `with_operator`) |
| `rules_set.rs`, `rules_set_phases`, `rules_set_properties`, `rules_exceptions` | `rules_set/` (`mod`, `phases`, `properties`, `exceptions`) |
| `anchored_variable`, `anchored_set_variable`, `anchored_set_variable_translation_proxy`; the `variable_value` / `variable_origin` re-exports | `variables/` |
| `modsecurity.rs` (`modsecurity::modsecurity`) | `instance.rs` (`ModSecurity`, the log callback types, version and log-property constants) and `phases.rs` (`Phases`, `NUMBER_OF_PHASES`) |

Ten files remain at the root: `lib`, `instance`, `phases`, `transaction`,
`intervention`, `debug_log`, `run_time_string`, `unique_id`,
`http_support`, `middleware`.

## `Regex` without integer results (PLAN.md step 6)

The PCRE2 wrapper (`modsecurity_native::regex`) answered with integers
and an error state the caller had to check:

| Was | Now |
|---|---|
| `Regex::with_options(..)` then `has_error()` | `Regex::compile(pattern, ignore_case, multi_line) -> Result<Regex, CompileError>` (the pattern as text, for the messages); `has_error` is private |
| `search(s) -> i32` (1 or 0), compared with `> 0`, `!= 0` or `<= 0`; the free function `regex_search` | `is_match(s) -> bool` |
| `search_one_match` / `search_global` -> `RegexResult { Ok, ErrorMatchLimit, ErrorOther }` | `-> Result<(), MatchError>` (`MatchLimit`, `Other`); a `Result` cannot be ignored silently |
| `search_match` (no callers) | removed |

`Regex::new`, `new_case` and `with_options` stay for the patterns of the
configuration whose errors the C++ code ignores (key exclusions,
`ARGS:/re/` selectors, `SecAuditLogRelevantStatus`, ...): an invalid
pattern still gives a regex that never matches, as documented on them.
`@rx` and `@rxGlobal` keep `Option<Result<Regex, CompileError>>`, so a
pattern that fails to compile is still reported when the operator runs;
`@verifyCC` fails its `init`, as before.

## Typed log flags

The Rust API took the C++ `LogProperty` and `LogMessageInfo` values as
`i32` constants, and `RuleMessage::log` a status code where -1 meant "keep
the `%d` placeholder". They are `bitflags` types now:
`LogProperties` (`TEXT`, `RULE_MESSAGE`, `INCLUDE_FULL_HIGHLIGHT`) for
`ModSecurity::set_server_log_cb_with_properties`, and `LogParts`
(`CLIENT`, `ERROR_LOG_TAIL`) with an `Option<i32>` code for
`RuleMessage::log`. The bits are those of the C++ enumerations. The C API
never passed these values, so it is unchanged.

## Settings declared once

`RulesSetProperties` had 23 `Option` fields for the single valued settings
(`SecRuleEngine`, `SecRequestBodyLimit`, ...), and `merge_properties`
merged each with a hand-written line: a new setting could be added without
its merge. They are now `RulesSetProperties::settings`, a `Settings` struct
declared by the `settings!` macro, which generates the fields and
`merge_unset` from one list. `SecRemoteRulesFailAction` stays outside: it
is not merged (as in C++).

## `Rule`, and the entries of a rule set

The type every part of the engine handles was called `RuleWithActions`,
after the C++ class, and `Rule` was an enum of that and `RuleMarker`. A
marker is not a rule (no actions, never chained): it is a position in the
rule list. So:

- `Rule` (`src/rule/mod.rs`) is a `SecRule`, `SecAction` or
  `SecRuleScript`, told apart by `RuleKind::{SecRule, SecAction,
  SecRuleScript}`; `SecRule` (variables and operator) and `Script` are the
  parts only those kinds have (`rule::sec_rule`, `rule::sec_rule_script`).
- `rules_set::entry::Entry` is what a rule set lists: `Entry::Rule` or
  `Entry::Marker` (`rules_set::marker::Marker`).

Names only; no behavior change.

## An explicit "fails without a report"

Setting up the audit log could return an empty error string, which the
rule-set merge took to mean "failed, but C++ says nothing here; accept the
configuration" (a storage directory name with a NUL byte, which C++ cannot
pass to `mkdir`). That is now `audit_log::SetupError::{Reported(message),
Unreported}`, and `create_dir` returns `Option<String>` as its error. A
check for an empty error from the unicode map loader, which never returns
one, is gone. The other `String` errors stay strings: see "Decided
against" in `PLAN.md`.


## One debug log interface

Each extraction left its own copy of the debug log macro (`ms_dbg_a!`,
`act_dbg!`, `op_dbg!`, `mp_dbg!`, `xml_dbg!`, and two `_opt` forms), and
each context trait declared `debug_enabled` and `debug` again. There is now
one of each, in `modsecurity-types` (`debug.rs`):

- `DebugSink` has the two methods. `Transaction`, `ActionContext` and
  `MatchContext` implement it, and the context traits of the operators and
  of the multipart and XML processors have it as their supertrait.
- `ms_dbg!(sink, level, "...")` formats the message only when the level is
  logged, and takes the sink by value or by reference; `ms_dbg_opt!` takes
  an `Option`.

The operators and body crates depend on `modsecurity-types` for it. The
messages and their order are unchanged (the differential test compares
the debug log line by line).

## Typed audit log parts

The parts of an audit log entry were `i32` bit masks
(`AuditLog::A_AUDIT_LOG_PART` ... `Z_AUDIT_LOG_PART`, tested with
`parts & X != 0`). They are `audit_log::Parts` now, a `bitflags` type with
the same bit values (`Parts::A` ... `Parts::Z`, `Parts::DEFAULT`,
`Parts::from_letters`); the debug log still shows a set as its number
(`parts.bits()`).

- `ctl:auditLogParts` reads its letters when the rule is loaded, and a
  transaction keeps `(PartsChange, Parts)` instead of the text;
  `PartsChange::apply` replaces `AuditLog::add_parts` / `remove_parts`.
- `AuditLog::save_if_relevant` takes the parts. It took an `Option`, whose
  `None` meant "the configured parts, or all of them when none are
  configured" (C++ `m_parts` of -1); the one caller always passed them.
- The file and directory modes are `u32`, converted where the directive
  is read instead of where the files are created.

## One `Operator` trait

After the operators moved to their crate the engine still had its own
`Operator` trait, implemented by `@geoLookup`, `@inspectFile` and a
`Matcher` wrapper that forwarded every method to the crate's trait. The
engine's `operators::operator::Operator` is now an enum of those three
cases (`Matcher(Box<dyn modsecurity_operators::Operator>)`, `GeoLookup`,
`InspectFile`), so there is one operator trait, in the crate. The two
engine operators take the transaction directly, and
`MatchContext::transaction` (the way around the context) is gone.

## Workspace housekeeping

- The crates of the engine take `version`, `edition` and `license` from
  `[workspace.package]` (the nginx connector and the vendored libinjection
  keep their own versions).
- `modsecurity-collections` forbids `unsafe_code` like the other crates
  without C calls; it was the one that did not say so.
- `.github/workflows/ci.yml` runs `cargo fmt --check`, and clippy and the
  tests for the default, `--no-default-features` and `--all-features`
  builds. The differential test, the CRS suite, the fuzz targets and the
  benchmarks stay manual (they need the C++ library, nginx or an idle
  machine).

Not done: `[workspace.lints]` for `unsafe_code`. Cargo applies a package's
lints to all its targets, and the engine's regression runner
(`test/regression/regression.rs`) sets an environment variable, which is
`unsafe`; the `#![forbid(unsafe_code)]` attribute on each library says
exactly what is meant.

## The multipart parser, reworked inside

The parser was the C++ one transcribed: 15 `flag_*` integers used as
booleans, integer states, a fixed buffer with a write position and a
"bytes left" counter, a four byte `reserve` whose first byte was a count,
and five functions of 180 to 300 lines. It is the same line-oriented
state machine with the same C string rules, written with Rust types:

- `multipart/` is a directory: `mod.rs` (the state machine over the lines,
  and what is reported when the body ends), `content_type.rs` (the
  boundary from the Content-Type header), `part.rs` (a part: its header
  lines and its data), `content_disposition.rs`, `tmp_file.rs`.
- The flags are a `Flags` struct of `bool`s (`unmatched_boundary` keeps its
  0/1/2), the states are `PartState` and `LineEnd`, the buffer is a
  `Vec<u8>` holding the line, and the line break held back between pieces
  of data is a `&'static [u8]` (`b""`, `b"\n"` or `b"\r\n"`).
- `Multipart::fail` logs an error and records it, where each of about 30
  places formatted the message twice. The flags are reported from a list.
- The longest function is 120 lines (`read_boundary`); the others are
  under 75.

`count_boundary_params` returns `usize`. The parser's behavior is
unchanged, checked three ways:

- `tests/multipart.rs` runs the parser alone with a recording context
  (`tests/support`) on 54 bodies and compares everything it reports with
  `tests/data/multipart.trace`, written by the parser before the rework.
- While reworking, a copy of the old parser ran next to the new one on
  the body fuzz corpus (2555 inputs) and on mutations of it, in one piece
  and in chunks, with uploads off, saved, kept, limited and failing:
  613,040 bodies, then 313,045 more after the last change, all with
  identical traces. (That comparison was a scratch test; it is not in the
  repository, since it needs the old code.)
- The differential test against C++ and the `body` fuzz target.

## The actions by name, in the actions family

The parser built the actions with a plain value in a 173-line `match` of
its builder (`plain_action`, with `ctl` and `macro_action` next to it): the
last name table that was not with its family. It is
`actions::seclang` now:

- `PLAIN` is a table: for each action name, the values it takes (`bare`,
  `number`, `quoted_text`, `word`, ...: the token shapes of the C++
  scanner, each a small function) and how it is built.
- `plain(name, text)` and `with_macros(name, string)` return the action or
  the message to report. `ParsedAction` and `split_actions` moved with
  them.
- `ctl:auditEngine=On|RelevantOnly` makes the audit log set itself up even
  when `SecAuditEngine` is off. The parser still does that, from the
  action built (`AuditEngine::status`), where the table used to reach into
  the parser's properties.

Compared with `parser::tests::dump_outcomes` (see its documentation): the
real configurations and 9915 generated lines build the same, byte for
byte, before and after.

## The setting directives, declared once

A directive that is a keyword and a value was spread over three places of
the parser's builder: a table from the keyword to an `Effect` and the
patterns of its value, the `Effect` enum (60 variants), and two long
`match`es from the `Effect` to what it does. And the patterns themselves
(a second, hand-written lexer next to the grammar) had no tests.

- `modsecurity_seclang::value` has the shapes of values: `Class`,
  `Pattern`, `Extract`, and `read` / `word`, which give the value or say
  what is wrong with the text (`Refused::NotAValue`, `Refused::Trailing`).
  The helpers that trim a value (`sanitize`, `remove_brackets_if_needed`)
  moved there from the engine's `utils::string`. Nine unit tests cover the
  shapes and the quirks they keep from the C++ scanner (`SecWebAppId "my
  app"` is `my app"`, checked against the C++ library).
- `src/parser/settings.rs` has one entry per directive: how its value is
  written, and what it does (a function, `Ignored` or `Unsupported`). The
  `Effect` enum, `apply_choice` and `apply_value` are gone.
- `src/parser/build.rs` went from 1604 to 551 lines over this and the
  previous section.

`parser::tests::dump_outcomes` is byte-identical before and after; a
planted change in one setting changes 147 lines of it.

## Leftovers of the extractions

- The engine's manifest listed `bstr` and `libinjection`, which nothing
  in it uses any more.
- Three modules were shells. `engine/` held only Lua: it is `src/lua.rs`.
  `request_body_processor/` re-exported the `modsecurity-body` crate and
  held the tests through a transaction: the engine names the crate, and
  the tests are `transaction/body/tests/`. `utils` re-exported `regex`,
  `libxml2`, `base64`, the URL decoder, `json` and `unordered_multimap`
  from three crates: their users name the crates.
- The layout table of `MIGRATION.md` described the tree as first ported;
  it shows where the C++ code is now.

## Request body processing in steps

`Transaction::process_request_body` was one function of 202 lines: it
chose a processor, ran it, reported its result in four copies of the same
few lines, checked whether the rules get the body, and set the body
variables. It is 20 lines now, and `transaction/body.rs` has the steps:

- `request_body_processor` says which `Processor` parses the body (`Xml`,
  `Json`, `Multipart`, `UrlEncoded`, `Missing` for a known type without a
  processor, `None`);
- `parse_xml_body` and `parse_json_body` return `Result<(), String>`, and
  `set_reqbody_result` reports any of them (`REQBODY_ERROR`,
  `REQBODY_PROCESSOR_ERROR` and their messages); `parse_multipart_body`
  also reports form data over `SecRequestBodyNoFilesLimit`;
- `request_body_access` and `set_request_body_variables` are the two
  steps after parsing.

The XML and multipart processors write to the transaction while they read
the body, so the body was copied for them. It is taken out of the
transaction for the call and put back instead (nothing reads it
meanwhile).

Checked by running the old function (kept as a test-only method for the
comparison, then removed) and the new one on the body fuzz corpus as each
of six content types and none, with the body limit and body access
settings and `ctl:requestBodyAccess` varied: 76,636 requests with the
same debug log at level 9 and the same intervention.

## Actions are given their name and payload

The text of an action was split twice: the parser's table checked the
shape of `name:value`, then each action's constructor split the same text
again (`name_and_payload` or `name_of`, in about 50 constructors). The
constructors now take what they need: `Skip::new(name, payload)`,
`Deny::new(name)`, `InitCol::with_rts(name, payload, string)`. The text is
split in two places, `actions::seclang::plain` and the parser's `initcol`;
`name_of` is gone.

An action still keeps its name as written (`DENY` stays `DENY`): the
debug log prints it, and `block` and `setvar` are recognised by it.

`parser::tests::dump_outcomes` is byte-identical before and after.

## A type for rule ids

A rule's id was an `i64` compared in five places with the `i32` ids of
the `ctl:` actions through `as i64`, looked up as an `f64` for the
`SecRuleUpdate...ById` directives, and narrowed with an unexplained `as
i32` for `SecRuleRemoveById`. `rule::Id` wraps the `i64` and has each of
those comparisons as a method that says what C++ does there (`is`,
`is_within`, `as_number`, `narrowed`). Its `Debug` and `Display` print
the number, so logs and dumps are unchanged.

The narrowing is C++ behavior (`RulesExceptions::contains(int)` is given
the 64 bit id): rule 4294967297 is removed by `SecRuleRemoveById 1`, but
not by `ctl:ruleRemoveById=1`. Checked against the C++ library; a test
keeps it.

Severities, status codes and skip counts stay `i32`: the directives
accept any `int` for them, as in C++, so a narrower type would change
what is accepted.

## The nginx connector: handlers as safe code

The connector was the C module transcribed: each handler was one `unsafe`
block reading and writing nginx's structures through raw pointers. Now:

- `connectors/nginx/src/nginx.rs` is nginx as the handlers see it:
  `Request` (made from the pointer nginx gives a handler; the connection,
  the request line and headers, the request body, the response headers
  nginx will send, the module's configuration and context slots), `Log`
  and `Buffers` (the buffers of a chain). Every access to an nginx
  structure is in a method there, with its `SAFETY` comment.
- The handlers are an `extern "C"` entry point that makes the `Request`
  and finds the context, and safe functions for the work:
  `process_request_line_and_headers`, `next_step`, `inspect_body`,
  `inspect_headers`, `process_intervention`.
- The access handler no longer holds a reference to the context while
  nginx reads the request body: that call can run
  `ngx_http_modsecurity_request_read`, which reads the context.
- `Ctx::create` and `Ctx::find` replace the two free functions; the
  context no longer keeps the request pointer (nothing read it).

The directives, the phases and what is sent to ModSecurity, in which
order, are unchanged. The number of `unsafe` blocks is not lower (they
are smaller, one per nginx access): what changed is where they are.

The files are named after what they hold, not after the C files:
`module.rs`, `context.rs`, `access.rs`, `header_filter.rs`,
`body_filter.rs`, `log.rs`, `intervention.rs`, `nginx.rs`. The exported
`ngx_http_modsecurity_module` symbol keeps its name.

## `@geoLookup` in the operators crate

`@geoLookup` stayed in the engine when the operators were extracted,
because it reads the rule set's database and fills the transaction's
`GEO` collection. It is in `modsecurity-operators` now
(`geo_lookup.rs`), with the database type (`GeoDb`, was
`utils::geo_lookup`) and a `maxmind` feature that the engine's feature of
the same name enables. The operator's `Context` has two more methods:
`geo_db`, the database of `SecGeoLookupDb`, and `set_geo`. The rule set
still owns the database (the parser opens it, merged rule sets share
it); the tests of that are with the directive, in `parser/settings.rs`.

The engine's `Operator` is a matcher of the crate or `@inspectFile`,
which stays: its Lua half runs the engine's Lua binding with the
transaction. The engine no longer depends on `maxminddb` and
`dns-lookup` itself.

## `@ipMatch` without the C++ crit-bit tree

The port of the C++ crit-bit tree (`modsecurity_compat::msc_tree`, about
650 lines) is gone, and with it the `ipmatch-prefix-trie` feature that
offered the alternative: the prefix tries are the only implementation.
This changes which addresses match a list of overlapping networks (the
tree missed some): see "Intentional deviations from C++" in
`MIGRATION.md`.

The set is `modsecurity_operators::ip_set::IpSet`, in the crate of its
only user, and holds what `ip_tree::IpTree` and `msc_tree::TreeRoot` did.
`prefix-trie` and `ipnet` are dependencies of the operators crate; the
compat crate has no dependency left. The seven functions that read an
entry (four of them public, for the two implementations in two crates)
are three private ones: `parse_entry`, `parse_v4`, `parse_v6`.

The entries of a list are no longer read as C++ reads them either: an
entry is an address or `address/length`, parsed with the standard library
and `ipnet` (`parse_address`, `parse_entry`). Which lists load changes
with that (`/0` and `::1/128` are accepted, `/24abc` is not): the second
`@ipMatch` item of "Intentional deviations from C++" in `MIGRATION.md`.

## One `c_str`

"The bytes up to the first NUL byte" was written out in 21 places: four
named helpers (`cstr`, `cstr_prefix`, two `c_str`) and seventeen inline
`position(|&c| c == 0)`. There is one now,
`modsecurity_compat::chars::c_str`, used by the engine and the operators,
body and transformations crates. `modsecurity-native` (below the compat
crate) and the nginx connector (a C boundary of its own) have one private
copy each, and the C API's `strdup` keeps its own cut.

No behavior changed. Each remaining use is a place where C++ hands a
string to C code, so what follows a NUL byte is ignored there: the audit
log, Lua, `@inspectFile`'s argument, `@rbl`, `@geoLookup`, `@fuzzyHash`
lists, `@detectSQLi`'s fingerprint, the multipart parser, base64
decoding, regular expression patterns, the unicode map file, downloaded
rules, the HTTPS audit log body. Whether each of those should keep that
is a question of behavior, case by case.

## `@pm` without the C++ matcher

The port of ACMP (`modsecurity_compat::acmp`, 460 lines) is gone, and
with it the `pm-aho-corasick` feature: the `aho-corasick` crate is the
only phrase matcher of `@pm`, `@pmFromFile` and `@pmf`, and a required
dependency of the operators crate. This changes which phrases are found
and reported: see "Intentional deviations from C++" in `MIGRATION.md`.


## Helpers that were one standard call

Helper functions that only called one standard function under another
name are gone, and their callers call the standard one:
`valid_hex` (`u8::is_ascii_hexdigit`, 20 calls), `lossy`
(`String::from_utf8_lossy`, 41), `tolower` and `toupper_str`
(`to_ascii_lowercase` / `to_ascii_uppercase`, 8), `double_to_string`
(`format!("{:.6}", x)`, 3), `asc_time` (`strftime_local(t, "%c")`), and
`random_number` / `generate_transaction_unique_id` (one `random_range`
call; `utils/random.rs` is gone).

`utils/md5.rs` and `utils/sha1.rs`, where MD5 was defined in terms of a
generic type of the SHA-1 file, are `utils/hash.rs` with two functions,
`md5_hex` and `sha1_hex`.

Kept, because they are not a standard call: `isodigit` (the standard
`is_ascii_octdigit` is not stable), `is_space` (C's `isspace` includes
the vertical tab, `is_ascii_whitespace` does not), `find` / `find_from`
(a search in bytes), `x2c`, `hex2dec`, `chomp`, `limit_to`, and the C
number conversions of `cnum`.

## Rule ids are integers

The `id` action kept its value as an `f64`, parsed like C++ `std::stod`
and checked by printing it back with `%.40g`, for which
`cnum::format_g` (and a test helper calling `snprintf`) existed. It is
an `i64` parsed by the standard library; `format_g` is gone. Which ids
are accepted changes at the edges: see "Intentional deviations from C++"
in `MIGRATION.md`.

## One way to read a rule id

`rule::Id::parse` reads an id for the `id` action,
`SecRuleUpdateTargetById` and `SecRuleUpdateActionById`; the two
directives kept a C++ `double` (`cnum::stod`), and their tables were keyed
by its bit pattern. They are keyed by `rule::Id` now, the code page of
`SecUnicodeMapFile` is a `u32`, and `stod` is gone. See "Intentional
deviations from C++" in `MIGRATION.md`.

## A NUL byte is a byte

`chars::c_str` (cut at the first NUL byte) is left only where a value
goes to C as a C string or where a test of the original suite expects
the cut (`t:base64Decode`). The multipart parser no longer reads its
lines and headers as C strings: `c_at` and `c_starts_with` are gone, the
cursor of the Content-Disposition parser gives `Option<u8>`, and "the end
of the line" is the end of the slice. See "Intentional deviations from
C++" in `MIGRATION.md`.


## The rule plan (step 1)

A rule alone does not say what runs: its transformations depend on
`SecDefaultAction` and `SecRuleUpdateActionById`, its targets on the
`SecRuleUpdateTarget...` directives, and the `SecRuleRemove...` directives
decide whether it runs. The evaluation used to work all of this out for
every rule of every transaction (`Rule::for_each_transformation`,
`SecRule::final_vars`, the removal checks of `RulesSet::evaluate`).

`rules_set::plan` works it out once per rule set: `Plan::compile` gives,
for each phase, the steps (`Step::Marker`, `Step::Rule` with a `Link` per
rule of the chain, `Step::Removed`), and a `Link` holds the rule's
effective transformations, their path, and its targets. `RulesSet::plan`
compiles it the first time a transaction needs it and a new load or merge
discards it. The evaluation follows the plan and only looks at what a
transaction can change (`ctl:` actions).

Step 2 added what the rule set contributes to a rule's actions: a `Link`
also holds the `SecDefaultAction` actions that run on a match, the
disruptive one (which is what `block` runs: `Block` has no behavior of
its own any more, the rule runs `Link::block_actions`), and the actions
`SecRuleUpdateActionById` adds. Whether a rule "contains block" is the
rule's own flag: the code that looked for a `block` among the
transformations that `SecRuleUpdateActionById` adds could never find one
and is gone.

Not in the plan: the rule's own actions stay in the rule, in the slots
`Rule::new` sorts them into, and the variables and operators themselves.

## The run time actions of a rule: `rule::Actions`

A rule kept its run time actions in seven fields (the disruptive action,
`logdata`, `msg`, `severity`, the tags, the `setvar`s and the rest), and
the order they run in was spelled out by the function that ran them.
`rule::Actions` (`src/rule/actions.rs`) holds them as they run: the
`setvar`s, which run on every match of the operator, and one list for a
matched chain, kept in order (tags, `severity`, `logdata`, `msg`, the
others as written, the disruptive action). The functions that run the
actions moved there from `rule/mod.rs`. No behavior change.

## A rule message is data; the logs render it

`RuleMessage` could only be turned into a log line: its fields were
private to the crate, so an embedder that wanted the rule id, the tags or
the severity of a match had to parse the text. It now has accessors for
the rule (`rule_id`, `rule_location`, `rev`, `ver`, `maturity`,
`accuracy`), for what the rule says about the match (`message`, `data`,
`severity`, `tags`, `is_disruptive`) and for what matched (`operator`,
`operator_parameter`, `variable`, `reference`). `Transaction::rule_messages`
gives every message of a transaction; the server log callback gets the
ones that do not interrupt when it asks for `LogProperties::RULE_MESSAGE`.

`rule/message.rs` became a directory: `mod.rs` is the message, `text.rs`
the error log line and the `H` lines of the native audit log, `json.rs`
the entry of `messages` in the JSON audit log (it was written out in
`audit_log/format.rs`). No behavior change.

## A staged API: `modsecurity::inspection`

`Transaction` has the shape of the C API: any of its `process_*` and
`add_*` methods can be called at any time, and nothing makes the caller
ask for the intervention after a phase. `inspection` puts the order in
types, on top of it: `Inspection` → `RequestHead` → `RequestBody` →
`ResponseHead` → `ResponseBody`. A step consumes its stage and gives
`Result<next stage, Blocked>`, so `?` carries an intervention out; the
logging phase runs when the last value of the exchange is dropped (after
the last step, when a `Blocked` goes away, on `abort(status)`, or when a
stage is abandoned).

The tower middleware is written with it (its tests are unchanged), and it
is what the README and the crate documentation show first. `Transaction`
is unchanged: the C API and the nginx connector use it directly.

## A rule id is a `u64`

`rule::Id` was a wrapper around an `i64` with `is(i32)` and
`is_within(i32, i32)`: the id was signed because the C++ field was, and
the two methods compared it with the 32 bit ids that `ctl:ruleRemoveById`
and `ctl:ruleRemoveTargetById` kept. Those actions now hold ids like
everything else, so `Id` is an alias of `u64`, and `rule::id` has the two
functions that say how ids are written: `parse` (one id) and `parse_list`
(the ids and ranges of `SecRuleRemoveById` and `ctl:ruleRemoveById`,
which each had a copy of that parser). A transaction keeps the rules
removed by `ctl:ruleRemoveById` as one list of ranges instead of a list of
ids and a list of ranges.


## Operators are built ready

An operator was made in two steps: `X::new(param)`, then a fallible
`Operator::init(file, resources)` that compiled the regular expression or
loaded the file. Between the two the value existed half built, and each
operator had its own answer for being evaluated in that state. Construction
is fallible instead: those constructors return `Result<Self, String>` with
the messages `init` had, and take the configuration file name and the
`Resources` when they need them. `instantiate` returns
`Option<Result<_, String>>` (`None`: no such operator), in the operators
crate and in the engine, and `@inspectFile` is built the same way. `@rx` and
`@rxGlobal` are one type, `Rx`, with two constructors.


## Fallible variable construction

`new_variable` returns `Result<Variable, VariableError>` (`Unknown`,
`InvalidRegex`); selector regexes are compiled by
`variables::selector_regex` with `Regex::compile`; `KeyExclusion::regex`
and `AuditLog::set_relevant_status` return errors the parser reports as
configuration errors. A merged audit log shares the compiled
relevant-status regex through an `Arc`.


## One parser and one comparison for names

`Persistent::parse` (case-insensitive) replaces `Persistent::from_name`
and is the only way collection names are read; `key_exclusions::same_name`
is the one comparison for removing a target by name. `ExpireVar` keeps its
expression parsed (`Expiry`) when it has no macro.


## Optional rule id and severity

`Rule::rule_id: Option<Id>`, `Rule::severity() -> Option<u8>`,
`RuleMessage::{rule_id, severity}` return `Option`; `Rule::logged_id()`
gives what logs print (0 for none). `IdMultimap::for_rule` and
`RulesExceptions::contains` take `impl Into<Option<Id>>`.


## SecDefaultAction across loads

`RulesSet::driver()` seeds each load's `Driver` with the phases that
already have a `SecDefaultAction`, so a second one for a phase is refused
across loads as within one.


## The nginx module exports its own module tables

`connectors/nginx/src/lib.rs` exports `ngx_modules`, `ngx_module_names`
and `ngx_module_order` (as `auto/module` generates them for the C module)
instead of `ngx::ngx_modules!`, whose order list is empty. The order is
that of the C module's `config`: the filters run after copy, headers and
postpone, and before gzip. The `ngx` crate is no longer a dependency;
configurations are moved into the nginx pool by `module::pool_move`, which
checks both allocations before writing. `test/nginx/smoke.sh` checks the
order in a running nginx.


## Panics stop at the C boundary

Every function nginx calls in the connector runs under
`nginx::catch_panic` (log, then a 500 or a configuration error), and every
`msc_*` function under `capi::catch_panic` (its error value). A
`CTransaction` wraps the engine's transaction with a `failed` flag: after a
panic, later calls do nothing and `msc_intervention` reports a disruptive
500 (fail closed). The C API
crate denies `clippy::undocumented_unsafe_blocks`. `msc_new_transaction*`
check for NULL, and `msc_rules_merge(x, x)` is a no-op returning 0.


## Rules are loaded as bytes

`RulesSet::load_bytes(&[u8], reference)` is the loading entry point
(`load`/`load_with_ref` are str wrappers), `RulesSet::load_file(&Path)`
takes file names that are not UTF-8, and `load_remote` loads the
downloaded bytes. The C API and the nginx directives use them.
`Driver::parse(&str)` is test-only.


## Hex digits are `Option`s; decoders without C sentinels

`modsecurity_compat::chars::{hex_digit, hex_pair}` replace `hex2dec` (-1),
`xsingle2c` and `x2c`. Every decoder that checks its digits uses them;
only t:hexDecode keeps its unchecked arithmetic, in hex_decode.rs, because
the unit suite expects it. `Base64::decode_forgiven` is one pass and
returns `Vec<u8>`. t:escapeSeqDecode decodes to `Option<(byte, len)>`.
`urldecode_nonstrict_inplace(_ext)` returns the invalid-escape count.
Outputs were compared with the old code on 1.57M generated inputs per
decoder before the old code was removed.


## Substring search is memchr's

`chars::find`/`find_from` use `memchr::memmem`. @contains, @containsWord
and @strmatch keep a `memmem::Finder` built in the constructor when their
parameter has no macro (`needle.rs`). The multipart parser uses
`chars::find`.


## libxml2 schemas and DTDs are parsed once

`libxml2::Schema` (Send) joins `Dtd` (now Send).
`Document::validate_schema` takes a parsed schema.
`libxml2::external_entities_allowed()` mirrors the thread's loader
setting. @validateSchema and @validateDTD keep the first file they load
with external entities allowed, behind a Mutex: libxml2 promises no
concurrent use, and DTD validation writes content models into the DTD.
With external entities off they load, and fail, per evaluation as before.


## libinjection results are a `Detection` enum

`libinjection_adapter::{detect_sqli, detect_xss}` return `Detection<F>
{Clean, Attack(F), ParserError}`. The per-thread overrides that force
parser errors in the unit suite are in the `#[doc(hidden)]
libinjection_adapter::testing` module, re-exported through
`modsecurity::internal::libinjection_testing`. libinjection_utils is
merged into the adapter.


## Benchmarks compare named builds

`test/benchmark/build_variant.sh NAME [REV]` builds the C API library of a
commit (in its own worktree) or of the working tree into
`target/benchmark/variants/NAME`; `run_library.sh` runs the `VARIANTS` it
is given, interleaved over `REPS` rounds, and `summarize.py` prints best
and median per scenario against the first variant. `run_nginx.sh` checks
the status of every response and fails on an unexpected one.


## Body processors: argument-name allowance

`crates/modsecurity-body/src/names.rs` (`NameBudget`) bounds the total
size of the argument names a JSON or XML body may produce: 1 MiB plus 64
bytes per body byte. JSON takes it per `Json::parse` call; XML grows it
with each `process_chunk`. Exceeding it is a processor error (see
MIGRATION.md).


## Multipart field values

`PartKind::Field` holds nothing: a field's data goes straight into
`MultipartPart::value` as it is read, instead of one allocation per line
joined at the part's end. `Multipart::process` takes the body in pieces
with each piece's offset and gives the same results as the whole body
(test `one_byte_at_a_time`).


## In-memory collection sweep

`InMemoryPerProcess` deletes keys whose entries have all expired when an
insert brings the map to twice what the last sweep left (at least 1024
entries); readers still purge what they meet. Constant cost per write on
average; memory stays within about twice the live entries.


## modsecurity-body public API

Only what the engine uses is public: the three processors with their
`Context` traits, `Flag`, `Entries`, `Uploads`, `MultipartPartTmpFile`
(`release`, `filename`) and `Multipart::reqbody_no_files_length`.
`Xml::has_doc` is gone (use `document().is_some()`).


## SecLang values without what surrounds them

Directive values used to be matched together with the white space and
quotes around them and then cleaned afterwards, as Strings (`sanitize`,
`remove_brackets_if_needed`), in five places: the setting reader,
SecMarker, `build.rs`'s SecRuleUpdate.../SecRuleScript paths (which first
re-attached `Value::lead`), `rule::id::parse_list`, and Include. Now each
pattern of `value::read` captures its value as a slice of the line
(`value::Match`). The only choice left is `value::Quotes` (whether single
quotes are quotes). The grammar gives update selectors and script paths
unquoted. The cleaning helpers, `Extract`/`Part`, `Value::lead` and
`parser_sanitizer` are gone. The refactor commit was checked against the
old reader on 316.6M generated inputs and the old engine on 4.2M generated
lines, with identical results. The quirks the old code kept were removed
in three separate behavior-change commits (see MIGRATION.md).


## Interventions

`intervention.rs` has the public `Intervention` (status, url, log as a
`String`: what `Transaction::intervention` hands out, always disruptive;
no `Default`, no `disruptive` field) and the internal
`PendingIntervention` enum (None / Status / Disruptive). An
`InterventionLog` holds a fixed text or a rule message's line in two parts
around the status code. Actions use `ActionContext::disrupt(status, url)`
and `intervention_status() -> Option<u16>`. The C API sets `disruptive =
1` when it fills its struct.


## AnchoredVariable

Fields are private; the value lives only in its `VariableValue`, and
`value()`/`offset()` read it. `set*` replaces the origin;
`set_adding_origins` is for values computed from several places
(ARGS_COMBINED_SIZE, FILES_COMBINED_SIZE). `VariableValue::clear_origins`
was added.


## Body append

`Transaction::append_body(BodyDirection, buf)` holds the limit logic for
both bodies; `append_request_body`/`append_response_body` keep their debug
lines and the response's content-type check.


## Middleware streaming

The middleware reads bodies frame by frame up to the end or the limit
(`inspection::{RequestBody,ResponseBody}::limit_reached`) and passes them
on as `middleware::InspectedBody<B>`, which is the frames read and then
the rest. The inner service takes `Request<InspectedBody<ReqBody>>`, and
`ResponseBody<B> = Either<Full<Bytes>, InspectedBody<B>>`. Trailers are
forwarded.


## Types

`ArgumentOrigin` {Get, Post, Json, Xml}; `Option<RequestBodyType>`
{Multipart, UrlEncoded} for the Content-Type and
`Option<RequestBodyProcessor>` {Json, Xml} for `ctl:requestBodyProcessor`;
`Outcome::highest_severity: Option<u8>` with `highest_severity_value()`
giving 255 when none.


## Transaction variables declared once

Each variable of the transaction (`REQUEST_METHOD`, `ARGS`, ...) used to
be written three times: a field of the struct, its name in the
constructor, and a row of the lookup tables (`variables/names.rs`) that
repeated the name and the field. `variables/table.rs` now has one line
per variable, `field: "TOKEN"` plus the row fields that differ from the
defaults (`{ lua: false }`, `{ name: "UNIQUEID" }`), and a
`macro_rules!` makes the struct (`TransactionVariables`), its
constructor and the rows (`SINGLE`, `MULTI`). SecLang-only aliases
(`STATUS`, `STATUS_LINE`, `MULTIPART_SEMICOLON_MISSING`) are rows
without a field.

`ARGS_NAMES`, `ARGS_GET_NAMES` and `ARGS_POST_NAMES` are no longer fields
holding a proxy: a multi valued variable declared with `names` stores the
name values, and `MultiVariable::names()` is the view that resolves them.
The proxy's other path (translate the whole result list when it was not
empty) was unreachable, since every caller passes an empty list, and is
gone.

The C++ names went with it: `TransactionAnchoredVariables` is
`TransactionVariables`, `AnchoredVariable` is `SingleVariable`
(`variables::single`) and `AnchoredSetVariable` is `MultiVariable`
(`variables::multi`).


## Matched variables and `ctl:` removals have one owner

`MATCHED_VAR`, `MATCHED_VAR_NAME`, `MATCHED_VARS` and
`MATCHED_VARS_NAMES` were set by `SecRule::update_matched_vars` and
cleared by `RulesSet::clean_matched_vars`, each reaching into the
transaction's variables. They are `TransactionVariables::record_match`
and `clear_matches` now.

`CtlOverrides` moved to `src/transaction/ctl.rs` with its constructor
and the three questions its callers asked by reading its lists:
`removes_rule_id`, `removes_rule_by_tag` and `removes_target`. The
target predicate was written twice in `sec_rule.rs` (for a target and
for a value); it is written once.


## Rule evaluation in `crate::eval`

How rules run was spread over the types they are made of:
`RulesSet::evaluate` (the phase walk), `Marker::evaluate`, `Rule::evaluate`,
`evaluate_with_message`, `evaluate_base`, `execute_transformations` and
`perform_logging`, `SecRule::evaluate`, `sec_action::evaluate`,
`Script::evaluate`, and the action runners of `rule/actions.rs`, each
passing the rule, its `Link`, the transaction and the rule message to
the next. The evaluation state (`EvalState`, `EvalScratch`) was in
`transaction.rs`.

All of it is in `src/eval/` now:

- `mod.rs`: `EvalState` and `EvalScratch`;
- `phase.rs`: the walk over a phase (skip, `skipAfter` and markers,
  `allow`, removed rules, the stop after a disruption);
- `rule.rs`: `RuleRun`, one rule being evaluated (rule, `Link`, the
  plan of its chain, transaction, rule message), with the `SecAction`
  and `SecRuleScript` kinds, the transformations and the logging;
- `sec_rule.rs`: the `SecRule` kind;
- `actions.rs`: the actions on a match and on the chain's match.

`rule/` and `rules_set/` hold what the configuration says and the
queries asked of it at load time; `rule/sec_action.rs` is gone. A
`SecRuleScript` still keeps the matched values (`capture`) of the rule
before it, as before: only `SecRule` and `SecAction` clear them.


## `Rule`: `Chain` and `Metadata`

A rule's place in a chain was three fields: `is_chained` (the `chain`
action), `chained_rule_child` and `chained_rule_parent`, a bool whose C++
name (a pointer there) suggested a rule. They are one `Chain`:
`continued`, `next` and `is_continuation`. What a rule says about itself
for the logs (`rev`, `ver`, `accuracy`, `maturity`) is a `Metadata`.
Renames only.


## A redb backend for the persistent collections

`modsecurity-collections` has a third backend, `backend::redb::Redb`,
behind the opt-in `redb` feature (the engine's feature of the same name).
It keeps the collections in `./modsec-shared-collections.redb`, opened in
redb's multi-writer mode (stable since redb 4.5): any number of
processes read and write it, one write transaction at a time, as nginx's
workers do with LMDB's file. Records are `CollectionData::serialize`,
as with LMDB, in one table of byte keys; keys are walked in order, so
the prefix and regex lookups work as LMDB's. With both features on,
redb is used. The default stays LMDB until the two have been compared
in production-like use.

`StorageError` carries a text (`cause`) instead of an LMDB code, so
that a backend reports what its storage said; LMDB's is `code N`, the
same debug log line as before.

Measured on 2026-11-24 (WSL2, ext4; 100 keys x 10 rounds of
`resolve_first` then `store_or_update_first` per process, as
`setvar:ip.x=+1` does; durability is a sync on every commit in both):

| | LMDB | redb |
|---|---|---|
| read, one process | 4.7-8.0 us | 15.3-15.4 us |
| read, four processes | 4.8-5.8 us | 20.8-23.0 us |
| write, one process | 1.17-1.58 ms | 1.36-1.41 ms |
| write, four processes | 3.5-5.3 ms | 6.0-6.5 ms |
| walk of 500 entries | 70-150 us | 110-230 us |

Writes cost the sync of the commit in both. A test runs four processes
writing to one file while the test process has it open.


## `transaction.rs` split by direction

`transaction.rs` had every method a connector calls. The request side
(connection, URI, headers, body, appending the body or reading it from a
file) is in `transaction/request.rs`, the response side (status,
headers, body) in `transaction/response.rs`, and the transaction's
argument methods joined `ArgumentWriter` in `transaction/arguments.rs`.
`transaction.rs` keeps the state, the constructors, running a phase,
the body buffers both directions share, the logging phase and the
intervention. Each submodule imports what it uses. Moves only: the code
lines are the same.


## The HTTPS client on `ureq`

`utils::https_client` (`SecRemoteRules`, the HTTPS audit log writer, the
remote `@pmFromFile`/`@ipMatchFromFile` lists) used libcurl through the
`curl` crate, which needs the system library and its headers. It uses
`ureq` 3 with rustls now, and checks certificates against the platform's
trust store (`rustls-platform-verifier`), as libcurl does; a bundled list
(`webpki-roots`) would not know an organisation's own CA. What libcurl
was asked for is kept: TLS 1.2 at least (rustls has nothing older), peer
and host checks, the `ModSec-*` headers and the `ModSecurity3` user agent,
a failed download on an HTTP error status, POST with the request type (or
a form's type, as libcurl's default), no `Expect: 100-continue`, a body
of any size (`ureq` stops at 10 MB unless told otherwise), and a proxy
from the environment. One difference: `ureq` takes the first of
`ALL_PROXY`, `HTTPS_PROXY`, `HTTP_PROXY` that is set, whatever the
scheme, where libcurl picks by scheme.

The cargo feature is `https-client`; `curl` stays as its alias in the
engine and the C API, so that existing build commands keep working.


## Rule properties are not actions

`id`, `phase`, `rev`, `ver`, `accuracy`, `maturity` and `chain` were
seven action types of `Kind::Configuration`: they never ran, and
`Rule::new` called their `configure(&mut Rule)` to set a field. They
are one `rule::Property` now (with the name as written, `RuleProperty`),
which the parser builds in their place and `Rule::new` applies. With
them gone, an action was either a transformation or ran on a match, so
`Kind`, `Action::kind` and `Action::configure` are gone too:
`RuleAction::is_transformation` tells the two apart.
`SecDefaultAction` takes the `phase` property and refuses the others,
and `SecRuleUpdateActionById` refuses all of them, with the messages as
before (the parser checks them now, where the update list was checked).
`capture` and `multiMatch` stay actions: the two directives accept them
(they have no effect there), and making them properties would refuse
configurations that load today.


## One load builds a `RulesSet`

The parser's `Driver` held the same two parts as `RulesSet`
(`RulesSetProperties` and `RulesSetPhases`), and a rule set merged a
driver through `merge_driver`, a rule set through `merge`, both through
`merge_parts`. A `Driver` holds a `RulesSet` now (`rules`), next to what
only parsing needs (the file names, the last rule for `chain`, the
phases that have a `SecDefaultAction` already), and a successful load is
merged with `RulesSet::merge`: one way to merge.


## `lua.rs` is a module

`src/lua.rs` (909 lines) is `src/lua/`: `engine.rs` compiles a script
once and runs it in a fresh Lua state; `api.rs` has the `m.*` functions;
`lauxlib.rs` reproduces what Lua's C API does for them (the argument
checks and their messages, `lua_tostring`, `lua_type`); `disabled.rs` is
the engine of a build without the `lua` feature; the tests are in
`tests.rs`. Moves only.


## Settings declared with typed helpers

The table of setting directives (`parser/settings.rs`, `directive`) was
one closure per directive, 324 lines. A choice of words was written
twice: the words accepted, then an `if`/`else if` chain mapping them to
values whose last branch took everything else, so the two lists could
drift apart unnoticed. It is declared with helpers now: `choice` (each
word with the value it stands for), `on_off`, `limit` (a number, with
the directive's name in its error), `mode` (an octal file mode), `text`
and `only_off`; the directives with logic of their own keep a closure.
`Effect::Apply` is a boxed closure, so that a helper can carry its
table. Compared with the previous table on 70 directives x 33 values
(every setting and error message): identical.


## `RunTimeString`: `expand` and `text`

A string with macros had five ways to be read: `evaluate_rule(t, rule)`,
`evaluate(t)`, `evaluate_cow(t)`, `evaluate_static()` and
`evaluate_static_string()`, the transaction an `Option` throughout. Two
things are asked of it: the string in a transaction, and the string by
itself (a tag as written, a configuration value). They are
`expand(&Transaction, Option<&Rule>)` and `text()`, both a `Cow`, which
borrows a string without macros. The `SecRule` debug line that shows a
parameter with macros builds its text once.

