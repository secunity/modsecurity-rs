# C++ → Rust migration notes

Source: libmodsecurity v3.0.17 (`ModSecurity` repository, commit `1ebdc390`).

## Layout

The port started as the C++ tree file by file. It has been reorganized
since (`REFACTORING.md` has each step); this is where the C++ code is now:

| C++ | Rust |
|---|---|
| `headers/modsecurity/*.h` (public API) | the `modsecurity` crate (`src/`): `instance` (`ModSecurity`), `transaction`, `rules_set/` (`RulesSet`; `properties`, `exceptions`, `entry`, `marker`), `rule/` (`Rule`; `sec_rule`, `sec_action`, `sec_rule_script`, `message`), `intervention`, `phases` |
| the C API (`msc_*`) | `crates/modsecurity-capi` (`libmodsecurity.so.3`) |
| `headers/modsecurity/actions/action.h`, `src/actions/{,ctl,data,disruptive}/` | `src/actions/` (same subdirectories; `rule_action.rs` is the closed set of actions, `seclang.rs` builds them by name) |
| `src/actions/transformations/` | `crates/modsecurity-transformations` |
| `src/operators/` | `crates/modsecurity-operators`; `@inspectFile` in `src/operators/` |
| `src/variables/*.h` (one header per variable) | `src/variables/`: `variable.rs` (the target type), `names.rs` (the table of variables), and `persistent`, `rule`, `env`, `xml`, `computed` for the ones with logic of their own; `VariableValue` and `VariableOrigin` in `crates/modsecurity-types` |
| `headers/modsecurity/collection/*.h`, `src/collection/` | `crates/modsecurity-collections` |
| `headers/modsecurity/audit_log.h`, `src/audit_log/` | `src/audit_log/` |
| `headers/modsecurity/debug_log.h` | `src/debug_log.rs` |
| `src/request_body_processor/` | `crates/modsecurity-body` |
| `src/engine/lua.cc` | `src/lua.rs` |
| `src/parser/seclang-scanner.ll`, `seclang-parser.yy` | `crates/modsecurity-seclang` (a `pest` grammar, and the shapes of directive values) and `src/parser/` (`build.rs`, `settings.rs`: what the directives mean) |
| `src/parser/driver.cc` | `src/parser/driver.rs` |
| `src/utils/` | `src/utils/` (files, the HTTPS client, digests); the GeoIP database with `@geoLookup` in `crates/modsecurity-operators`; string and number helpers, ACMP and the IP tree in `crates/modsecurity-compat`; PCRE2 in `crates/modsecurity-native` |
| `others/libinjection` (C submodule) | `others/libinjection` (pure Rust crate) |
| `others/mbedtls` | `md-5` / `sha1` crates; base64 in `crates/modsecurity-transformations` |
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
- **Class hierarchies.** No Rust type emulates a C++ base class (a trait
  with `base()` accessors over an embedded struct):
  - *Actions* are an `Action` trait (`name`, `kind`, `configure`,
    `evaluate`); each action owns what it parsed from its payload, and its
    constructor does the parsing and returns `Result` (C++: construct, then
    `init(&error)`). A rule keeps the actions it treats specially in typed
    slots (`RuleAction`).
  - *Transformations* are one `Transformation { name, kind }` with a match
    over `TransformationKind`.
  - *Operators* are an `Operator` trait (`name`, `param`, `init`,
    `evaluate`); an operator with a parameter owns a `Param`. Negation
    (`!@op`) belongs to the rule (`RuleOperator`), not to the operator.
  - *Variables* (rule targets) are one `Variable` struct: its name, its key
    exclusions and a `Source` enum (transaction field, `*_NAMES` proxy, `TX`,
    persistent collection, `RULE`, `ENV`, `XML`, computed value, `!VAR`,
    `&VAR`). The ~100 classes the C++ `DEFINE_VARIABLE*` macros generate
    are rows of the table in `variables::new_variable`.
  - `Collection`, `DebugLog` and the Lua/libxml2 backends are traits or
    feature-gated modules; `Rule` (`Marker` | `WithActions`),
    `RuleWithActionsKind` (`Operator` | `Unconditional` | `Script`) and the
    audit log `Writer` are enums.
- **Sentinels and codes.** "Not set" is `Option` (configuration values,
  audit log settings, a rule's phase after an unknown `phase:<name>`);
  phases are the `Phases` enum; fallible operations return `Result`. The C
  API keeps its integer codes. Numbers that C++ prints are kept as numbers
  (`AuditLogStatus`, the multipart Content-Disposition error codes).
- **Macros.** `ms_dbg_a` became `ms_dbg!` (`modsecurity_types::ms_dbg`).
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
- **Shared mutable state.** Persistent collections and the log files are
  shared across transactions/threads, so they synchronise internally
  (`Mutex`/`RwLock`),
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
| `prefix-trie`, `ipnet` | the crit-bit tree of `msc_tree.c` | the networks of an `@ipMatch` list (an intentional deviation, see below) |
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
- **An audit log keeps its file after a merge that changes it**: when a
  later configuration merged into a rule set changed `SecAuditLog` (or
  `SecAuditLog2`), C++ released the new file with the previous writer (its
  destructor read the paths after the merge): the new log was closed, so
  nothing was audited, and the old file stayed open. Each writer now
  releases the files it opened.
- **Numbers beyond the `int` range** are read as C and C++ read them. The
  Rust engine let them wrap around modulo 2^64, so it accepted
  configurations the C++ library rejects and gave limits another value:
  `skip:18446744073709551617` was `skip:1` (C++: "is not a number"), and
  likewise `accuracy`, `maturity`, `severity`, `status`,
  `ctl:ruleRemoveById`, `ctl:ruleRemoveTargetById` and `SecRuleRemoveById`
  (which also truncated ids between 2^31 and 2^63);
  `SecArgumentsLimit 18446744073709551617` and
  `SecRequestBodyJsonDepthLimit` were a limit of 1 (C++: `atoi` saturates,
  no effective limit). They now use `std::stoi` and `atoi` semantics
  (`modsecurity_compat::cnum`), checked against the C++ library on these
  inputs. One case goes beyond C++: `phase:` with a number beyond `int`
  crashes the C++ library (the exception is not caught); it is an
  "Unknown phase" error here (it used to give a rule that never runs).
- **Unusual entries of a `SecUnicodeMapFile`** are read as C++ reads
  them (`strtok_r(.., ":")`, then `(int) strtol(.., 16)` for the code and
  the map). The Rust engine read a sign or an overflowing number as 0, so
  `-41:42` and `fffffffffffffffff:43` mapped code point 0 (C++: out of
  range, no entry) and `0041:-42` mapped to byte 0 (C++: to byte 0xBE);
  `:42` was code 0 mapped to 0x42 (C++ skips the leading colon: code 0x42
  without a map); and a NUL byte did not end the file. The shipped
  `unicode.mapping` has no such entries. An entry made only of colons
  crashes C++ and is ignored here.
- **Each rule set has its own GeoIP database**: C++ keeps one database
  per process, set by the last `SecGeoLookupDb` loaded anywhere, so
  `@geoLookup` in one rule set used the database of another (and which one
  depended on load order), and `SecGeoLookupDb` with a file that cannot be
  opened was accepted once any configuration had opened one. The database is
  now a setting of the rule set, merged like the others (a rule set keeps its
  own and inherits a merged one's, e.g. an nginx location its parent's). A
  rule set without one, merged or its own, does not look up anything
  (`Database is not open. Use: SecGeoLookupDb directive.`), and a file that
  cannot be opened is an error unless the same configuration opened a
  database before it.
- **libxml2 documents left in a parser context are freed**: C++ leaked the
  document libxml2 builds for the entities of an internal DTD while parsing
  XML into ARGS (`SecParseXmlIntoArgs`), and the document of a request whose
  body never completed (found by the `body` fuzz target).
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
- **`@ipMatch`, `@ipMatchFromFile`, `@ipMatchF` with overlapping networks.**
  *C++:* the networks are kept in a crit-bit tree inherited from
  ModSecurity v2. Its netmask arrays are reset whenever a netmask is added
  to a node, a prefix that exists with another netmask is ignored, and
  only the first netmask of a node is applied, so an address inside a
  listed network goes unmatched when overlapping networks are listed with
  it: `@ipMatch 10.0.49.87/16,10.0.42.94/18` does not match `10.0.70.67`.
  *Here:* the networks are kept in prefix tries (`prefix-trie`, `ipnet`),
  and an address matches whenever a listed network contains it. *Why:* an
  allow or block list that silently misses addresses is a security bug,
  and nothing can depend on which addresses the tree happens to miss.
  (Which entries a list accepts is the next item.) The port of the tree was compared with the tries before it was
  removed, on 24,000 generated lists and 288,000 lookups: identical for
  lists of addresses, of disjoint networks and of nested networks; for
  overlapping networks the only differences were 1,303 lookups that the
  tree missed and the tries match, each inside a listed network. (Earlier,
  against C++ v3.0.15 through the C API on 300 random lists: the tree port
  identical to C++, the tries 142 extra matches.) Until this change the
  tries were the opt-in `ipmatch-prefix-trie` feature, which no longer
  exists. Regression test: `ip_set::tests::overlapping_networks` and
  `matches_cidr_containment` in `modsecurity-operators`.
- **The entries of an `@ipMatch`, `@ipMatchFromFile` or `@ipMatchF` list.**
  *C++ (`TreeAddIP`):* the prefix length is read with `atoi` and 0 is
  refused, the entry is copied to a buffer of 32 bytes (IPv4) or 128
  (IPv6), and an IPv6 entry keeps its `/128` when the address is parsed.
  So `1.2.3.4/0` and `::1/128` are refused, `1.2.3.4/24abc`, `1.2.3.4/+8`
  and `1.2.3.4/24/5` are accepted as `/24`, `/8` and `/24`, and a longer
  entry is cut. *Here:* an entry is an address, or `address/length` with
  a length of decimal digits from 0 to 32 (IPv4) or 128 (IPv6), whatever
  its size. `/0` is every address of the family and `::1/128` is `::1`;
  a length with anything but digits is refused, and the rule does not
  load. *Why:* the owner does not want the accidents of the C code kept;
  the C++ regression and unit tests only list plain addresses and `/32`.
  Unchanged: the address syntax (that of `inet_pton`: no leading zeros,
  no short forms, no spaces), a netmask written as an address is refused
  (`/255.0.0.0`), an empty length is refused, and entries and values end
  at a NUL byte. Compared with the C++-compatible reader before it was
  removed, on 60,504 generated entries: 57,556 read the same, none read
  as another network; 586 newly accepted (`/0`, an explicit IPv6 `/128`,
  entries longer than the C buffers) and 2,267 newly refused (text after
  or before the digits of the length). Regression tests:
  `ip_set::tests::entry_parsing` and `everything` in
  `modsecurity-operators`.
- **Time formatting** (audit/error log timestamps, the JSON `time_stamp`,
  parallel audit log and upload directory names) always uses the C locale's
  formats and English names. C++'s `strftime` follows the process `LC_TIME`
  locale, so the output only differs if the embedding application calls
  `setlocale` (nginx does not). The local zone is read from `TZ` or
  `/etc/localtime` as with libc; the output was checked to be identical to
  glibc's across 1970–2040 in several zones.
- `xmlCleanupParser()` is not called when a `ModSecurity` instance is
  dropped (unsafe with several instances).
- **SecLang parser** (`src/parser/seclang.pest`, see `REFACTORING.md`):
  every real configuration builds the same rules as with the C++
  flex/bison parser, with these differences:
  - Syntax error messages and their line/column differ.
  - Junk that the flex scanner skipped (printing the bytes to stdout) or
    misread is rejected, e.g. `SecRule% ARGS ...`, `"@lt 3""`,
    `"@lt' 3"`, `!"@rx a"`, `SecRule ARGS "@rx" (a)"`; nothing is printed
    to stdout.
  - `setvar:tx.a=\%{x}` sets `TX:a` to `\%{x}` instead of making
    `a=\%{x}` the key.
- **Rule line numbers** (error log `[line "N"]`, the debug log's rule
  locations) are the line of the rule's keyword. The C++ scanner did not
  count the line feeds inside quoted texts (a multi-line `msg` or operator),
  between a rule's variables and its operator or between `SecAction` and its
  actions on the next line, after `SecRuleUpdateTargetBy*` (with the blank
  lines that follow), a blank line after a rule without actions, nor the
  blank lines after a commented out `SecRule ... \`, so the rules after
  those were reported too early (CRS: from 1 to 13 lines). The differential
  test compares line numbers out.
- **A directive or a comment right after a rule without actions** starts a
  new statement. The C++ scanner read the line after such a rule as its
  actions, so `SecRule ...` / `#...` there was a syntax error ("Expecting an
  action"); a blank line was needed. Actions on that line are still the
  rule's actions, as in C++.
- **A whole collection followed by text** is the collection followed by the
  text. The C++ grammar read the text as the collection's key: `SecRule TX
  "foo"` (a regular expression after `TX`, `IP`, `SESSION`, ...) failed to
  load, and in a macro `%{tx}x` was `TX:x` (the rest of the string as the
  key).
- **`%` that does not start a macro** is a plain character everywhere. The
  C++ scanner rejected it between single quotes and in an unquoted operator
  (`msg:'100%'` failed to load), and elsewhere took the next character with
  it, so `"@contains 5%" "id:1"` did not end at the operator's quote and
  `tag:a%,pass` swallowed the comma. `%{VAR}%` is still the variable (a `%`
  right after a macro belongs to it, as in C++; the regression tests use
  that form).
- **An action list without its closing quote** is a syntax error. The C++
  scanner ended the list at the end of the line, so `"id:1,phase:2,pass`
  loaded. (Seven upstream regression tests had the typo in their rules;
  their quotes are added.)
- **`phase:'request'`** is phase 2. The C++ scanner built an `allow` action
  from it (its `allow` rule also matches `phase:'request'` and comes
  first), so the rule ran in phase 1 and allowed the transaction. The
  quoted `phase:'phase'` (accepted as `allow` by C++) is an error.
- **Unknown operators** are a syntax error. The C++ scanner read an
  unknown `@name` (a typo such as `@containz`), and a parameter given to an
  operator that takes none (`@detectSQLi x`), as a regular expression of
  the whole text, so the rule silently matched `@containz ...` literally.
  A regular expression that starts with `@` followed by something else than
  a letter is still one.
- **`\"` in a double-quoted operator parameter** is a quote (upstream issue
  3750, PR 3753): `"@contains test()\"quote\""` matches `test()"quote"`. The
  C++ scanner kept the backslash, so the operator looked for `\"`. The
  parameters of `@rx`/`@rxGlobal` (and bare regular expressions) are kept
  as written, as they appear in the logs: PCRE already reads `\"` as `"`
  (except inside `\Q..\E`, which still sees the backslash). `\\` stays two
  backslashes. In CRS 4.8 this makes rule 955350 (`@contains <h1
  style=\"margin-bottom: 0\">webadmin.php</h1>`, a web shell's page) able to
  match. Action values are unchanged (the regression
  test `misc-escaped-quote-after-macro-expansion.json` pins the backslash
  there).

Faithfully *kept* C++ quirks are documented at their site (e.g.
`SecRuleRemoveById` compares range bounds as strings, setvar/`stoi`
semantics).

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
