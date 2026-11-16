# Restructuring plan

Where the crate split stands, what is left, and how each step has been
done so far. Updated on 2026-11-16 at commit `cf443a9`. `REFACTORING.md`
has the details of every finished step; this file is the map and the
to-do list.

## Where things stand

The engine began as one crate. It is now ten, and the engine itself has
no `unsafe` code.

| Crate | Path | Lines | Contents |
|---|---|---|---|
| `modsecurity` | `.` | 18,100 | the engine and its Rust API |
| `modsecurity-native` | `crates/modsecurity-native` | 1,800 | all the `unsafe`: PCRE2, libxml2, LMDB, ssdeep, Lua, libc calls |
| `modsecurity-compat` | `crates/modsecurity-compat` | 3,500 | what reproduces C++ behavior: ACMP, the IP tree, the libstdc++-ordered multimap, yajl-style JSON, byte helpers (`chars`), number conversions (`cnum`), `strerror` |
| `modsecurity-transformations` | `crates/modsecurity-transformations` | 2,600 | the `t:` functions |
| `modsecurity-operators` | `crates/modsecurity-operators` | 3,600 | the 36 operators that only match |
| `modsecurity-body` | `crates/modsecurity-body` | 2,600 | the multipart, JSON and XML body processors |
| `modsecurity-types` | `crates/modsecurity-types` | 250 | `VariableValue`, `VariableOrigin`, the key exclusions |
| `modsecurity-collections` | `crates/modsecurity-collections` | 1,100 | the persistent collections (in-memory and LMDB backends) and the `TX` variables |
| `modsecurity-seclang` | `crates/modsecurity-seclang` | 400 | the grammar and the syntax tree |
| `modsecurity-capi` | `crates/modsecurity-capi` | 750 | the `msc_*` C API: `libmodsecurity.so.3` |

Also in the workspace: `connectors/nginx`, `examples/axum`, and
`others/libinjection`.

Dependencies point one way: `native` and `compat` at the bottom,
`transformations` on `compat`, `operators` and `body` on those, `types`
on `native` and `collections` on `types`, the engine on all of them,
`capi` on the engine.

## How each extraction was done

The same three steps every time. They are worth repeating exactly,
because each one is verified on its own.

1. **Narrow the interface in place.** Replace "takes the transaction" with
   a small context that offers only what the code needs. For operators
   that was `MatchContext` (later the `Context` trait); for the body
   processors, `multipart::Context` and `xml::Context`. The statements and
   their order do not change, so the debug log stays identical.
2. **Verify and commit that step alone.**
3. **Move the files** to the new crate, with the context as its trait and
   the engine implementing it. Tests that need a whole transaction stay in
   the engine; the crate gets tests against a small fake context.

Code that genuinely needs the engine stays there and says so. Two
operators do (`@geoLookup` fills the `GEO` collection, `@inspectFile`
runs Lua with the transaction); they reach it through
`MatchContext::transaction()`. Likewise three actions (`setvar`, `exec`,
`block`) use `ActionContext::engine()`.

## What is left, in suggested order

### 1. Actions in a crate (optional)

The actions that use only `ActionContext` could move to a crate, as the
operators did. What it would take: the macro strings of 11 actions
(`RunTimeString`, which resolves engine variables) behind an opaque type
the context expands; the parser applying the configuration actions (`id`,
`phase`, `rev`, ...) itself instead of `configure(&mut RuleWithActions)`;
and the engine enums they use (`Phases`, `Persistent`, `RequestBodyType`,
`AuditLogStatus`, ...) in `modsecurity-types`. `setvar`, `exec` and
`block` stay in the engine regardless. Most actions are a few lines, so
the gain is small next to the work.

## Decided against

- **Typed errors everywhere.** 55 signatures return `Result<_, String>`.
  No caller looks inside those strings: every one is printed as it is
  (the parser's error message, the C API's error string), and the
  regression tests compare the text. Enums would add types nobody
  matches on and a risk of changing the messages. The one place a
  string carried a signal (an empty error meaning "fails without a
  report", in the audit log setup) is typed now: `audit_log::SetupError`.
  The remaining `Err(String::new())` (`@ipMatch` with an invalid list)
  is a message that happens to be empty, as in C++.

## Open items

- **`strtol16` is not `cnum::strtoll`.** The hexadecimal parser of the
  unicode map file (`src/rules_set/properties.rs`) skips a `0x` prefix,
  gives 0 on overflow and ignores a sign, where `cnum::strtoll` (and C's
  `strtol`) differ on each. Folding it in changes what odd map files
  give: compare with the C++ library first, as its own commit.
- **PCRE2 reads one byte past the subject.** Fixed on our side (commit
  `9b84875`: a padded copy when the subject ends near a page boundary;
  `crates/modsecurity-native/tests/guard_page.rs` reproduces it). It may
  be worth reporting to PCRE2 with that test.
- **`modsecurity::internal`** is a hidden facade for the in-tree test
  tools. Each extraction is a chance to shrink it.

## Verification, and what was learned doing it

The rules are in `AGENT.md`. These points cost time to find out:

- **The release profile is `lto = "fat"`, `codegen-units = 1`.** Without
  LTO each crate split cost about 1% of throughput; with thin LTO some
  still did. With fat LTO crate boundaries are free. A release build of
  the C library takes about 30 seconds.
- **Benchmark with an A/A control.** Run the baseline library under two
  names next to the candidate. On the machine used so far, the control
  agreed with itself to about 0.5% on an idle machine; under other load,
  gaps of 2% appeared and disappeared. Compare only runs from the same
  interleaved session.
- **The differential also compares the audit logs** (native, JSON,
  concurrent) with C++. Before it did, nothing checked that output
  format beyond a few substrings in the regression suite.
- **Instruction counts (callgrind) are the steadier benchmark here**, but
  builds of identical code from different worktrees differ by up to about
  0.5% (`corpus_pl4`), so treat smaller differences as noise. A first
  10-round wall-clock run beyond 3% was noise every time on 2026-11-16:
  rerun that scenario alone with 20 rounds before concluding.
- **The debug log is compared line by line** by the differential. When a
  step rewrites logging calls, keep the statements in order; the
  differential is the check that matters most for these refactors.
- **Run the fuzz targets after touching operators or body processors.**
  The transaction target found the PCRE2 over-read; it had looked like a
  non-reproducing artifact twice before.
- **Compare the C library after every structural change:** exported
  symbols (`nm -D --defined-only`), `SONAME` and `NEEDED` (`readelf -d`)
  against the parent's build.
- **Paths on the first machine** (set your own): the C++ tree for
  `CPP_TREE`, a CRS checkout for `CRS_DIR`, an nginx source tree, `go-ftw`
  and `albedo` for `test/crs/run.sh`. `AGENT.md` and the scripts' headers
  say what each needs.
