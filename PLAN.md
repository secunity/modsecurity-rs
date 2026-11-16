# Restructuring plan

Where the crate split stands, what is left, and how each step has been
done so far. Written on 2026-11-16 at commit `6acc4f9`. `REFACTORING.md`
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

### 1. Split `Transaction`

`src/transaction.rs` is still the hub: one struct with 59 fields that mixes
four things. Nearly everything else in the engine takes `&mut Transaction`.

- **Request data:** the variables (`vars`), the collections, the bodies,
  addresses and URI.
- **Rule-evaluation state:** `skip_next`, `marker`, `allow_type`,
  `chained_rule_parents`, the `rule_remove_*` lists, `matched`,
  `eval_scratch`.
- **Body processing:** `xml`, `json`, `multipart_part_tmp_files`, the body
  type fields.
- **Logging and outcome:** `rules_messages`, the audit-log modifiers,
  `intervention`, the log callback data.

Suggested steps:
1. ~~Group the fields into named sub-structs inside `Transaction`, with no
   behavior change.~~ Done: `http`, `body`, `ctl`, `eval`, `outcome` (see
   `REFACTORING.md`).
2. ~~Give actions the same treatment operators got: an `ActionContext` that
   offers what actions do.~~ Done (`src/actions/context.rs`); `setvar`,
   `exec` and `block` still reach the transaction through
   `ActionContext::engine()`.
3. ~~Move the audit-log rendering into `audit_log`, reading from the
   transaction.~~ Done (`src/audit_log/format.rs`). The differential test
   now compares the audit logs with C++ too.

### 2. Actions

~~`src/actions` is 53 small files behind `Box<dyn Action>`; a closed
`enum Action` would remove the downcast hooks.~~ Done: `RuleAction` has
one variant per action type and the hooks are gone (see
`REFACTORING.md`). After the `ActionContext` of step 1, the actions
that only use it could become a crate, as the operators did.

### 3. Collections

~~`src/collection` can become a crate once `VariableValue` and
`VariableOrigin` sit in a small shared-types crate below it.~~ Done:
`modsecurity-types` and `modsecurity-collections` (see `REFACTORING.md`).
The engine reaches them under their old paths (`crate::variable_value`,
`crate::collection`).

### 4. One name table per family

Each family should own a single registry that the parser consults.

- **Operators:** the parser's `operator_name` table (`src/parser/build.rs`)
  duplicates the crate's `instantiate`. The crate should export the table
  (name, whether it takes a parameter).
- **Variables:** `variables::new_variable` and the by-name lookup used by
  Lua (`string_match_resolve`) are two tables.
- **Transformations:** done. Two lookups remain on purpose (they differ);
  both live in the crate.

### 5. Module layout of the engine

The top level still has 25 flat files that mirror C++ headers.

- `anchored_set_variable*`, `anchored_variable`, `variable_origin`,
  `variable_value` belong under `variables/`.
- `rule`, `rule_marker`, `rule_script`, `rule_unconditional`,
  `rule_with_actions`, `rule_with_operator`, `rule_message` belong under
  `rule/`. `RuleWithActions` still carries "Rule" and "RuleWithActions"
  sections from the C++ class hierarchy; it could be one `Rule` with a
  kind.
- `rules_set*` and `rules_exceptions` belong together.
- The module `modsecurity::modsecurity` could be named for what it holds.

### 6. C-shaped APIs

- `Regex::search` returns an `i32` that callers compare with `<= 0`, and
  constructors need `has_error()` checks. A `Result` from the constructor
  and `bool`/`Option` from searches would be the Rust shape.
- 55 signatures return `Result<_, String>`. Typed errors per layer.
- Log properties are `i32` bit flags.
- The rule-set properties are about 30 `Option` fields, each merged by a
  hand-written line.

## Open items

- ~~Three of the five engine-side operators could move to the operators
  crate.~~ Done: `@rbl`, `@validateDTD` and `@validateSchema` are in
  `modsecurity-operators` (`Context::httpbl_key`, `Context::xml_document`).
  `@inspectFile` (Lua with the whole transaction) and `@geoLookup` (fills
  `GEO` from the rule set's database) are engine features and stay.
- **`atoi` / `stoi` in the engine wrap on overflow.**
  `utils::string::atoi` and `stoi` wrap where glibc saturates. They differ
  from C only for numbers of 19 or more digits. `compat::cnum` has the
  faithful versions. Switching is a behavior change: it needs its own
  commit, a regression test, and an entry in `MIGRATION.md`.
- **Other number parsers not yet in `cnum`:** `strtol16`
  (`rules_set_properties.rs`), `strtol_to_byte` and `strtol_digits` (the
  transformations crate). They are specialized; check each against
  `cnum::strtoll` before merging.
- **CRS test 920390-1 is flaky.** The test backend resets the connection
  on its 64 KB POST and nginx answers 502. Run alone it failed 3 of 25
  times on `master` and 4 of 25 on a branch, so it is not caused by any
  change here, but it fails more often than "rare". Worth fixing in
  `test/crs/run.sh` or the backend.
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
  0.4% (`corpus_pl4`), so treat smaller differences as noise.
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
