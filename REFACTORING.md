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
  reopen/failure semantics. Replacing these with owned handles would require
  a separate decision about reconfiguration behavior.
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
