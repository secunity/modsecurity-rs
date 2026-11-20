# Architecture

How the code is organised today and what happens to a configuration and
to a request. For how it got here, see `REFACTORING.md`; for what differs
from the C++ library, `MIGRATION.md`; for the rules of working on it,
`CLAUDE.md`.

## The workspace

| Crate | Path | What it is |
|---|---|---|
| `modsecurity` | `.` (`src/`) | The engine and its Rust API. No `unsafe` code. |
| `modsecurity-seclang` | `crates/modsecurity-seclang` | The SecLang syntax: a pest grammar and the syntax tree it gives. Knows nothing of the engine. |
| `modsecurity-operators` | `crates/modsecurity-operators` | The operators that only match (`@rx`, `@pm`, `@ipMatch`, `@detectSQLi`, ...), written against a small `Context` trait. |
| `modsecurity-transformations` | `crates/modsecurity-transformations` | The `t:` transformations, as functions on bytes. |
| `modsecurity-body` | `crates/modsecurity-body` | The request body processors: multipart, JSON, XML. Each is written against its own `Context` trait. |
| `modsecurity-collections` | `crates/modsecurity-collections` | The persistent collections (`IP`, `SESSION`, `USER`, `GLOBAL`, `RESOURCE`) with an in-memory and an LMDB backend, and a transaction's `TX` variables. |
| `modsecurity-types` | `crates/modsecurity-types` | What the crates above share with the engine: `VariableValue`, `VariableOrigin`, key exclusions, the debug log interface (`DebugSink`, `ms_dbg!`). |
| `modsecurity-compat` | `crates/modsecurity-compat` | Code that reproduces a C or C++ library on purpose, because tests of the original ModSecurity depend on the result: a multimap that iterates like libstdc++'s, a JSON writer and parser that behave like yajl, C number parsing. |
| `modsecurity-native` | `crates/modsecurity-native` | Safe wrappers of the C libraries: PCRE2, libxml2, LMDB, ssdeep, Lua helpers, libc. With `modsecurity-capi`, the only place with `unsafe`. |
| `modsecurity-capi` | `crates/modsecurity-capi` | The C API (`msc_*`) over the engine: builds `libmodsecurity.so.3`. |
| `modsecurity-nginx` | `connectors/nginx` | The nginx module. It uses the engine's Rust API directly, not the C API. |
| `libinjection` | `others/libinjection` | SQL injection and XSS detection, in Rust, used by `@detectSQLi` and `@detectXSS`. |
| example | `examples/axum` | An axum server behind the tower middleware. |

Dependencies point one way. `native` is at the bottom; `compat` and
`types` are on it; `transformations`, `operators`, `body` and
`collections` are on those; the engine is on all of them and on
`seclang`; `capi` and the nginx connector are on the engine.

The crates that hold rule logic (`operators`, `transformations`, `body`)
do not see a transaction. Each asks for what it needs through a small
trait, and the engine implements it (`operators::operator::MatchContext`
for operators, for instance). That is what lets them be tested alone.

## From configuration text to a rule set

1. **Syntax.** `modsecurity-seclang` parses the text into a tree of
   directives (`SecRule`, `SecAction`, settings, `Include`, ...). Syntax
   errors come from here.
2. **Building.** `src/parser/build.rs` turns each directive into engine
   objects: variables (`src/variables/`), an operator
   (`src/operators/`), actions (`src/actions/seclang.rs`).
   `src/parser/settings.rs` holds one entry per configuration directive
   and what it sets. The result of one load is a `Driver`
   (`src/parser/driver.rs`): the rules of each phase and the properties.
3. **The rule set.** `RulesSet` (`src/rules_set/`) merges what each load
   produced. Its parts:
   - `phases.rs`: the rules, one list per phase. An entry is a rule or a
     `SecMarker`.
   - `properties.rs`: every setting (`SecRuleEngine`, body limits, audit
     log, debug log, unicode map, ...).
   - `exceptions.rs`: what `SecRuleRemoveBy*` and `SecRuleUpdate*`
     directives say about rules.
4. **The plan.** A rule alone does not say what runs: default actions,
   updates and removals are separate directives. `plan.rs` works that out
   once per rule set, the first time a transaction needs it, and a new
   load or merge discards it. For each phase it gives the steps (rule,
   removed rule, marker), and for each rule of a chain a `Link`: its
   effective transformations, its targets, and the actions the rule set
   adds to it.

A rule (`src/rule/`) is a `Rule` with a `RuleKind`: `SecRule` (targets
and an operator), `SecAction`, or `SecRuleScript` (Lua, `src/lua.rs`). A
chained rule owns its child. Its run time actions are a `rule::Actions`
(`src/rule/actions.rs`), kept in the order they run.

## A request

One HTTP exchange is one `Transaction` (`src/transaction.rs`). It borrows
the `ModSecurity` instance and the `RulesSet`, and holds:

- `http`: the exchange as reported (addresses, URI, bodies, status);
- `vars`: the variables rules inspect, one field per variable
  (`ARGS`, `REQUEST_HEADERS`, `MATCHED_VAR`, the `MULTIPART_*` flags, ...);
- `collections`: `TX` and the persistent collections;
- `ctl`: what `ctl:` actions changed for this transaction;
- `eval`: the state of the rule evaluation (skips, markers, the chain
  being evaluated);
- `outcome`: the intervention and the rule messages.

Callers drive it in one of three ways:

- `modsecurity::inspection` (`src/inspection.rs`): stages as types
  (`Inspection` → `RequestHead` → `RequestBody` → `ResponseHead` →
  `ResponseBody`). Each step gives the next stage or `Blocked`. This is
  the API for Rust callers.
- `modsecurity::middleware` (`src/middleware.rs`, the `tower` feature): a
  tower layer written with `inspection`.
- `Transaction`'s own methods (`process_uri`, `add_request_header`,
  `process_request_headers`, ...): what the C API and the nginx connector
  call.

### Phases

A phase is a point in the exchange where rules run: request headers (1),
request body (2), response headers (3), response body (4), logging (5).
Before phase 2 the body is parsed by the processor that the content type
or a `ctl:` action selects (`src/transaction/body.rs`, using
`modsecurity-body`); its results become variables.

For a phase, `RulesSet::evaluate` (`src/rules_set/mod.rs`) walks the
plan's steps and handles what is not a rule's business: `skip`,
`skipAfter` and markers, `allow`, removed rules, and stopping after a
disruptive intervention.

### One rule

`SecRule::evaluate` (`src/rule/sec_rule.rs`):

1. Takes the targets from the rule's `Link`, minus what `ctl:` actions
   removed for this transaction.
2. Resolves each target to values (`Variable::evaluate`,
   `src/variables/variable.rs`).
3. Applies the `Link`'s transformations to each value.
4. Runs the operator on the result.
5. On a match: records it in the rule message and in `MATCHED_VAR*`, and
   runs the `setvar`s.
6. If the rule matched and has a chained rule, evaluates that one; the
   chain matches when every rule of it does.
7. For a matched chain: runs the actions (default actions of the phase,
   tags, updates, `severity`/`logdata`/`msg`, the others, the disruptive
   action) and decides whether the message is logged.

A disruptive action writes the `Intervention` in the transaction's
outcome; the caller reads it after the phase.

## What comes out

- **The intervention** (`src/intervention.rs`): a status or a redirect.
- **Rule messages** (`src/rule/message/`): one per reported match, as
  data (rule id, message, severity, tags, the variable that matched).
  `Transaction::rule_messages` has all of them; the server log callback
  receives the ones that do not interrupt. `text.rs` and `json.rs` render
  a message for the logs.
- **The audit log** (`src/audit_log/`): written in the logging phase.
  `format.rs` produces the native and JSON entries; `writer/` has the
  serial, parallel (one file per transaction plus an index) and HTTPS
  writers.
- **The debug log** (`src/debug_log.rs`): what `ms_dbg!` writes, by level.

## Where the boundaries are

- **`unsafe`** is only in `modsecurity-native` (calls into C libraries)
  and `modsecurity-capi` (pointers from C callers). The engine crate
  forbids it.
- **The C API** is a thin layer: `crates/modsecurity-capi/src/` has one
  file per C object (`modsecurity.rs`, `rules_set.rs`, `transaction.rs`,
  `intervention.rs`), each converting arguments and calling the engine.
- **The nginx connector** (`connectors/nginx/src/`): `nginx.rs` is a safe
  layer over nginx's types; `module.rs` is configuration; `access.rs`,
  `header_filter.rs`, `body_filter.rs` and `log.rs` are the handlers, one
  per point where nginx calls the module.

## Tests and tools

| What | Where | Run by |
|---|---|---|
| Unit tests | next to the code, and `crates/*/tests/` | `cargo test` |
| The original ModSecurity's regression and unit suites | cases in `test/test-cases/`, runners in `test/regression/` and `test/unit/`, entry point `test/suites.rs` | `cargo test` |
| Comparison with the C++ library on CRS traffic (a report, not a gate) | `test/differential/` | `test/differential/run.sh` |
| OWASP CRS regression suite through nginx | `test/crs/` | `test/crs/run.sh` |
| Benchmarks | `test/benchmark/` | `run_library.sh`, `run_nginx.sh` |
| Fuzz targets (`seclang`, `transaction`, `body`) | `fuzz/` | `cargo +nightly fuzz run` |
| A configuration checker | `tools/rules-check/` | `modsec-rules-check` |

## Where to look

| To change | Start at |
|---|---|
| The syntax of a directive | `crates/modsecurity-seclang/src/` (grammar), `src/parser/settings.rs` (what a setting does) |
| An operator | `crates/modsecurity-operators/src/<name>.rs` |
| A transformation | `crates/modsecurity-transformations/src/<name>.rs` |
| An action | `src/actions/<name>.rs`; the table of actions is in `src/actions/seclang.rs` |
| A variable | `src/variables/` (`mod.rs` maps names to variables) |
| How rules of a phase are walked | `src/rules_set/mod.rs`, `src/rules_set/plan.rs` |
| How one rule is evaluated | `src/rule/sec_rule.rs`, `src/rule/actions.rs` |
| Body parsing | `crates/modsecurity-body/src/`, `src/transaction/body.rs` |
| Log output | `src/rule/message/`, `src/audit_log/` |
| The C API | `crates/modsecurity-capi/src/` |
| The nginx module | `connectors/nginx/src/` |
