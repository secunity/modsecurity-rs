# Plan

What is planned, on hold, or decided against, and what was learned
verifying changes. `ARCHITECTURE.md` describes the code as it is;
`REFACTORING.md` records each finished step (the crate split, which ended
on 2026-11-16, and the redesigns since); `MIGRATION.md` lists the
intentional behavior changes.

When a step here is done, move its record to `REFACTORING.md` (or
`MIGRATION.md`) and remove it from this file.

## Next

- **The C-style decoders, rewritten.** Four transformations still walk
  their input with C-style indices and flags:
  - `normalise_path.rs` (`t:normalisePath`, `t:normalisePathWin`): signed
    indices into the buffer;
  - `base64.rs` (`mbedtls_decode`, used by `t:base64Decode`);
  - `html_entity_decode.rs` (`t:htmlEntityDecode`);
  - `js_decode.rs` (`t:jsDecode`).

  All four are in `crates/modsecurity-transformations/src/`. Each is its
  own step: keep the old function in the step's tests, compare old and
  new on generated inputs, run the fuzz targets, and benchmark (they are
  on the request path).
- **The `SecRequestBodyNoFilesLimit` error message.** When the value does
  not parse, the message names `SecRequestsBodyNoFilesLimit` (an extra
  `s`, from C++; `src/parser/settings.rs`). The fix changes an error
  message, so it is its own commit with an entry in `MIGRATION.md`.

## Open questions

These are behavior questions, not refactors: each needs a decision first,
then a commit of its own with a test and an entry in `MIGRATION.md`.

- **`MULTIPART_FILE_LIMIT_EXCEEDED` is never set.** The multipart parser
  records the condition (`file_limit_exceeded` in
  `crates/modsecurity-body/src/multipart/`) and it counts towards
  `MULTIPART_STRICT_ERROR`, but the variable itself stays 0. Setting it
  would let rules see what they cannot see now.
- **`ctl:auditLogParts` accepts `|` as a sign.** Only `+` and `-` mean
  anything (add or remove parts), but the check in
  `src/actions/seclang.rs` also lets `|` through, and the action
  (`src/actions/ctl/audit_log_parts.rs`) treats it as `-`: it removes
  the parts.
- **Multipart header lines made of line ends.** `chomp` in
  `crates/modsecurity-body/src/multipart/part.rs` removes the trailing
  `\r` and `\n` of a header line, except when the line has nothing else
  (as C++'s `chomp` does). So a header `Name:\r\n` keeps the `\r\n` in
  its value.

## On hold

Raised and set aside by the owner; not to be started without asking.

- **`@validateJsonSchema`.** An operator like `@validateSchema` for JSON
  bodies, with the `jsonschema` crate.
- **Writing JSON with `serde_json`.** The audit log and the rule messages
  are written by the yajl-like writer in `modsecurity-compat`.

## Decided against

- **Actions in a crate.** The actions that use only `ActionContext` could
  move to a crate, as the operators did. What it would take: the macro
  strings of 11 actions (`RunTimeString`, which resolves engine variables)
  behind an opaque type the context expands, and the engine enums they
  use (`Phases`, `Persistent`, `RequestBodyType`, `AuditLogStatus`, ...)
  in `modsecurity-types`. `setvar` and `exec` (which use
  `ActionContext::engine()`) stay in the engine regardless. Most actions
  are a few lines, so the gain is small next to the work.
- **Typed errors everywhere.** Many signatures return `Result<_, String>`
  where no caller looks inside the string: every one is printed as it is
  (the parser's error message, the C API's error string), and the
  regression tests compare the text. Enums would add types nobody
  matches on and a risk of changing the messages. The one place a
  string carried a signal (an empty error meaning "fails without a
  report", in the audit log setup) is typed now: `audit_log::SetupError`.
  Errors that callers do tell apart are enums (`StorageError`,
  `Utf8Error`, `UrlEncodingError`, ...).

## Other open items

- **PCRE2 reads one byte past the subject.** Fixed on our side (commit
  `9b84875`: a padded copy when the subject ends near a page boundary;
  `crates/modsecurity-native/tests/guard_page.rs` reproduces it). It may
  be worth reporting to PCRE2 with that test.
- **`modsecurity::internal`** is a hidden facade for the in-tree test
  tools (`tools/rules-check`, the regression and unit runners). Shrink it
  when a change makes one of its items public or unnecessary.

## How a module was moved to a crate

The crate split used the same three steps every time; a later move
should too.

1. **Narrow the interface in place.** Replace "takes the transaction"
   with a small context that offers only what the code needs: the
   `Context` trait of `modsecurity-operators` (implemented by the
   engine's `MatchContext`), `multipart::Context` and `xml::Context` of
   `modsecurity-body`. The statements and their order do not change, so
   the debug log stays identical.
2. **Verify and commit that step alone.**
3. **Move the files** to the new crate, with the context as its trait and
   the engine implementing it. Tests that need a whole transaction stay
   in the engine; the crate gets tests against a small fake context.

Code that genuinely needs the engine stays there and says so:
`@inspectFile` (it runs Lua with the transaction) is an engine operator
(`src/operators/inspect_file.rs`).

## Verification, and what was learned doing it

The rules are in `CLAUDE.md`. These points cost time to find out:

- **The release profile is `lto = "fat"`, `codegen-units = 1`.** Without
  LTO each crate split cost about 1% of throughput; with thin LTO some
  still did. With fat LTO crate boundaries are free. A release build of
  the C library takes about 30 seconds.
- **Benchmark with an A/A control.** Run the baseline library under two
  names next to the candidate (`build_variant.sh control HEAD~1`). On the
  machine used so far, the control agreed with itself to about 0.5% on an
  idle machine; under other load, gaps of 2% appeared and disappeared.
  Compare only runs from the same interleaved session.
- **Instruction counts (callgrind) are the steadier benchmark here**, but
  builds of identical code differ by up to about 0.7% (`corpus_pl4`), so
  treat smaller differences as noise. A first 10-round wall-clock run
  beyond 3% was noise every time on 2026-11-16: rerun that scenario
  alone with 20 rounds before concluding.
- **The differential also compares the audit logs** (native, JSON,
  concurrent) with C++. Before it did, nothing checked that output
  format beyond a few substrings in the regression suite.
- **The debug log is compared line by line** by the differential. When a
  step rewrites logging calls, keep the statements in order; the
  differential is the check that matters most for these refactors.
- **Run the fuzz targets after touching operators or body processors.**
  The transaction target found the PCRE2 over-read; it had looked like a
  non-reproducing artifact twice before.
- **Compare the C library after every structural change:** exported
  symbols (`nm -D --defined-only`), `SONAME` and `NEEDED` (`readelf -d`)
  against the parent's build.
- **CI runs clippy from the latest stable toolchain**, which can be newer
  than the local one: run `cargo +<that version> clippy` before pushing.
- **Paths on the first machine** (set your own): the C++ tree for
  `CPP_TREE`, a CRS checkout for `CRS_DIR`, an nginx source tree, `go-ftw`
  and `albedo` for `test/crs/run.sh`. `CLAUDE.md` and the scripts' headers
  say what each needs.
