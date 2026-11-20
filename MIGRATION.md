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
| `aho-corasick` | ACMP (`acmp.cc`) | the phrase matcher of `@pm` (an intentional deviation, see below) |
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
- **`@pm`, `@pmFromFile`, `@pmf`: the phrase matcher.** *C++:* its own
  Aho-Corasick matcher (ACMP, from ModSecurity v2), whose fail links only
  look one level up. It misses some matches (`@pm aaBa B bcbA ccc` does
  not match `AAAb`, which contains `B`); it can report a phrase that is
  not in the list, the text of the trie node it stopped on (`@pm abcd bc`
  on `abcx` reports `abc`); it cuts the reported phrase at a NUL byte;
  and it reads phrase bytes as C `char`, so bytes >= 0x80 never match
  where `char` is signed (x86) and do where it is not (ARM). *Here:* the
  `aho-corasick` crate: every occurrence is found, the phrase reported
  (`TX:0` with `capture`, the matched data of the logs) is the phrase of
  the list that matched, whole, and bytes that are not ASCII are compared
  as they are on every platform. As before: the first match is the one
  that ends first, matching is ASCII case insensitive, empty phrases are
  ignored. *Why:* a list that misses phrases it contains is a detection
  bug, and nothing can rely on which ones are missed; approved by the
  owner. The port of ACMP (which agreed with C++ `acmp_process_quick` on
  200k random cases) was compared with the crate before it was removed,
  on 24,000 generated phrase lists and 192,000 searches: the crate
  matches whenever ACMP does, never the other way round. For lists of
  words (34 letters and signs) 66 of 48,000 searches differ, all in the
  phrase reported; for lists made to collide (4 letters) 8,706 differ:
  8,240 in the phrase reported, 328 where ACMP only saw a later match,
  138 where it saw none. Until this change the crate was the opt-in
  `pm-aho-corasick` feature, which no longer exists. The C++ regression
  and unit suites pass, and on the differential test (CRS, 60 requests)
  the results are identical to C++. Regression test:
  `pm::tests::where_acmp_differs` in `modsecurity-operators`.
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
  no short forms), a netmask written as an address is refused
  (`/255.0.0.0`), and an empty length is refused. Compared with the C++-compatible reader before it was
  removed, on 60,504 generated entries: 57,556 read the same, none read
  as another network; 586 newly accepted (`/0`, an explicit IPv6 `/128`,
  entries longer than the C buffers) and 2,267 newly refused (text after
  or before the digits of the length). Regression tests:
  `ip_set::tests::entry_parsing` and `everything` in
  `modsecurity-operators`.
- **Whitespace around `@ipMatch` entries.** *C++:* an entry is what is
  between two commas (and, in a file, the start of the line and a `#`),
  so `@ipMatch 1.2.3.4, 5.6.7.8`, a file line `127.0.0.1 # comment` and
  a file with CRLF line endings have an entry that is not an address,
  and the rule does not load. *Here:* the ASCII whitespace around an
  entry is not part of it, and those load. Whitespace inside an entry
  (`1.2.3.4 /8`) is still an error. *Why:* approved by the owner; it
  only makes lists load that did not. Regression test:
  `ip_set::tests::whitespace_around_entries`.
- **NUL bytes and `@ipMatch`.** *C++:* the list and the value are C
  strings, so both end at their first NUL byte: `@ipMatch 1.2.3.4`
  matches the value `1.2.3.4\0junk`, and what follows a NUL byte in a
  list is ignored. *Here:* a NUL byte is a byte like another: a value
  with one is not an address and matches no list, and an entry with one
  is invalid (the rule does not load). *Why:* approved by the owner; a
  value is an address or it is not. Note for rules on client-supplied
  values (a forwarded-for header): a value followed by a NUL byte no
  longer matches the address before it. Regression test:
  `ip_set::tests::nul_bytes`.
- **Which rule ids are accepted.** *C++:* the `id` action reads its
  value as a floating point number (`std::stod`) and accepts it when that
  number prints back as the same text with 40 significant digits. Of the
  digit strings the grammar lets through, that refuses an id with leading
  zeros (`id:007`) and every integer a double cannot hold exactly
  (`id:9007199254740993`, and `id:9223372036854775807`, the largest 64 bit
  integer), and accepts larger ones that it can (`id:9223372036854775808`,
  `id:18446744073709551616`), which the 64 bit id of the rule then cannot
  hold. *Here:* the id is a decimal integer up to 9223372036854775807;
  leading zeros are allowed (`id:007` is 7). *Why:* the owner does not
  want the accidents of the C++ code kept where its tests do not need
  them; the C++ suites and CRS only use plain integers. The C++ library
  was run on the eight ids of this entry and differs exactly as said.
  Regression test: `actions::rule_id::tests::init_and_configure`.
- **`SecRuleRemoveById` reads ids and ranges as numbers.** *C++:*
  - the bounds of a range are compared as text, so `SecRuleRemoveById
    5-10` is refused ("Invalid range") and `10-5` is accepted (and
    removes nothing);
  - each id is read as far as its digits go (`12abc` is 12);
  - ids are kept as 32 bit integers and a rule's 64 bit id is narrowed
    to compare, so `SecRuleRemoveById 1` also removes rule 4294967297,
    and an id above 2147483647 cannot be named.
  *Here:* an id is a decimal integer, as in the `id` action; a range
  needs `first <= last`; a rule is removed by its own id only. A list
  with an invalid item is refused as a whole. The tests of the original
  ModSecurity pass. Regression tests:
  `rules_set::exceptions::tests::load_ids`,
  `rule::id::tests::an_id_beyond_the_int_range`.
- **`SecRuleUpdateActionById` and `SecRuleUpdateTargetById`: several
  for one rule apply in the order of the configuration.** *C++:* they
  are kept in a hash table that puts a new entry in front of the others
  of the same rule, and merging rule sets (loading another file, a
  server or location block of a connector) walks that table and reverses
  them again. So the order in which a rule's added actions run, and in
  which its added targets are inspected, depends on how many times the
  configuration was merged. *Here:* always the order in which they are
  written. Regression test:
  `rules_set::exceptions::tests::updates_are_in_the_order_of_the_configuration`.
- **Nothing is written to standard output or standard error** by the
  library (apart from `msc_rules_dump`, whose purpose it is). *C++*
  prints in three situations, and the Rust engine did too:
  - `SecRuleUpdateActionById` with an action that makes the rule what it
    is (`id`, `phase`, `chain`, `rev`, `ver`, `maturity`, `accuracy`):
    "General failure" on standard output, and the action is ignored.
    *Here:* the configuration is refused, with an error that names the
    action.
  - A rule message when no server log callback is set: written to
    standard error. *Here:* there is no server log without a callback;
    the message is still in the audit log and in the transaction's rule
    messages.
  - A transformation among the actions of a rule built in code:
    "General failure". *Here:* it is one of the rule's transformations.
  Regression test:
  `rules_set::exceptions::tests::update_action_by_id_refuses_what_makes_the_rule`.
- **`block` and `xmlns` in capitals.** Action names ignore case, but
  *C++* recognises these two by their name in lower case afterwards. A
  `BLOCK` action was not treated as disruptive: it ran the disruptive
  action of `SecDefaultAction` even with `SecRuleEngine DetectionOnly`,
  so a request was denied in a mode that must only detect. An `XMLNS`
  action was ignored by `XML:/xpath` targets. *Here:* both are what they
  are however they are written. Regression test:
  `actions::block::tests::block_in_capitals_is_still_disruptive`.
- **Regular expression keys of persistent collections (`IP:/regex/`,
  `GLOBAL:/regex/`, ...).** *C++:* the expression is prefixed with the
  compartment of the transaction (`10.0.0.1::app::` + expression),
  compiled for every evaluation, and searched in the full keys of every
  compartment of the collection. So the compartment is read as an
  expression (`10.0.0.1` also matches the keys of `1000001`), an
  expression anchored with `^` never matches, and each evaluation walks
  the keys of all clients. *Here:* the expression compiled when the rule
  is loaded is matched with the names of the keys of the transaction's
  own compartment. *Why:* one client's rule must not select another
  client's keys, and `^` should work. The tests of the original
  ModSecurity (`collection-regular_expression_selection.json`) pass.
  Regression test:
  `variables::persistent::tests::regex_keys_of_a_persistent_collection`.
- **`SecRuleUpdateActionById` with an action that is not disruptive
  keeps the rule's disruptive action.** *C++:* any action the directive
  adds to a rule switches off the rule's own disruptive action (and its
  `block`): after `SecRuleUpdateActionById 942100 "tag:'reviewed'"`, rule
  942100 no longer denies anything. *Here:* the rule's disruptive action
  is replaced only when the directive brings a disruptive action (`pass`,
  `deny`, `redirect`, ...) or a `block`. *Why:* adding a tag or a
  `setvar` to a rule should not disarm it. This makes the engine block
  where C++ does not. Regression test:
  `rules_set::plan::tests::an_update_replaces_the_disruptive_action_only_with_another`.
- **Directives that select rules by tag or message match them as
  written.** `SecRuleRemoveByTag`, `SecRuleRemoveByMsg`,
  `SecRuleUpdateTargetByTag` and `SecRuleUpdateTargetByMsg` name a tag or
  a message. *C++:* for every transaction, each rule's tags and message
  are expanded (macros such as `%{tx.kind}` get their value of the
  moment) and compared with the name. *Here:* the comparison is made once
  for the rule set, with the tag or message as written, a macro expanding
  to nothing: `SecRuleRemoveByTag attack-sqli` no longer removes a rule
  tagged `%{tx.kind}-sqli` when `tx.kind` happens to be `attack`. *Why:*
  which rules a configuration removes or retargets is a property of the
  configuration (it is part of the rule plan, see `REFACTORING.md`), not
  of a request. Tags and messages of CRS that these directives are used
  with have no macros. `ctl:ruleRemoveByTag` and
  `ctl:ruleRemoveTargetByTag`, which act during a transaction, still
  expand them. Regression test:
  `rules_set::plan::tests::tags_and_messages_are_matched_as_written`.
- **NUL bytes elsewhere.** *C++:* many values pass through a C string
  and so end at their first NUL byte. *Here:* in the places below a NUL
  byte is a byte like another. *Why:* approved by the owner; what follows
  a NUL byte should not be hidden from a rule or a log. No test of the
  original ModSecurity depends on any of them.
  - *Audit log* (native: the request line, request and response header
    names and values; JSON: header names): written whole. C++ logs
    `X: before` for the header `X: before\0after`. Regression test:
    `audit_log::tests::nul_byte_in_a_header`.
  - *Multipart, the Content-Type header:* a NUL byte is a character of
    the header, so `boundary=XyZ\0abc` is refused ("Invalid boundary in
    C-T (characters)"); C++ parses the body with the boundary `XyZ`.
  - *Multipart, a line of the body:* a line is a boundary line only if
    it is one whole; `--XyZ\0junk` is not the boundary `XyZ` (in C++
    the line ends at the NUL byte), and a line that starts with `--`
    then has a NUL byte counts for `MULTIPART_UNMATCHED_BOUNDARY`.
    (A NUL byte in a part header was and is an error.) Regression test:
    the cases `nul bytes` and `header: nul byte` of
    `crates/modsecurity-body/tests/multipart.rs`. On 60,000 mutated
    bodies the parser gives the same result as before for all 45,909
    without a NUL byte, and differs for 1,941 of the 14,091 with one.
  - *Regular expressions:* a pattern with a NUL byte is compiled whole
    (C++: up to it). Regression test:
    `regex::tests::nul_byte_in_a_pattern`.
  - *`@geoLookup` and `@rbl`:* a value with a NUL byte is not an address
    or a host name (C++ looks up what precedes it).
  - *Read or sent whole:* a `SecUnicodeMapFile`, the rules downloaded
    by `SecRemoteRules`, the audit log entry posted by the HTTPS writer,
    the content given to `ModSecurity::process_content_offset`, and the
    names looked up in an LMDB collection.
  - *Kept:* `t:base64Decode` still stops at a NUL byte (a test of the
    original suite expects it), and so do the values handed to C
    libraries and the system as C strings (libxml2, ssdeep, the
    argument of `@inspectFile`, the C API, the nginx connector).
- **The id of `SecRuleUpdateTargetById` and `SecRuleUpdateActionById`,
  and the code page of `SecUnicodeMapFile`.** *C++:* each is read with
  `std::stod`: the longest floating point prefix of the text, so
  `SecRuleUpdateTargetById 942100abc`, `9.421e5`, `942100.0` and `0xE6014`
  all name the rule 942100, and `SecUnicodeMapFile unicode.mapping 20127x`
  is the code page 20127. *Here:* a decimal integer, as the `id` action
  takes it (the code page: up to 4294967295); anything else is a
  configuration error. *Why:* approved by the owner; an id is an integer,
  and a typo in one is better reported than guessed. No test of the
  original ModSecurity depends on it. Regression tests:
  `rule::id::tests::the_id_of_an_update_directive`,
  `parser::settings::unicode_map_tests::code_page`.
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
