This phase separates the Rust design from the original C++ class layout.
The compatibility target is the existing engine's inputs, configuration,
diagnostics, persistence format and C API. It does not reinterpret legacy
quirks as bugs to fix during a refactor.

Inspection identified these concrete changes, in implementation order:

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
