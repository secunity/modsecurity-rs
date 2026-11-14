This repository is a complete Rust implementation of libmodsecurity v3 (the ModSecurity web application firewall engine), with an nginx connector in `connectors/nginx`. It started as a port of the C++ library v3.0.17. The port is done: the C++ code base is now a behavioral reference, not a design template.

## Design freedom

- Design for Rust, not for the C++ layout. Module boundaries, type hierarchies, file organization, internal APIs and data representations may be redesigned when that makes the code clearer, safer, faster or easier to maintain. There is no need to keep a file per C++ header, C++ class names, or "Port of ..." structure.
- Prefer well-maintained crates over hand-written code when they do the job. Before replacing an implementation, confirm the crate has the same semantics on the inputs that matter (compare both on generated inputs), and record the reason for each new dependency in `Cargo.toml`.
- Prefer safe Rust. Keep `unsafe` at the boundaries (C API, native libraries) with a `SAFETY` comment on every block. The crate denies `unsafe_code`; only `capi` and the native-library wrapper modules allow it (`#[allow(unsafe_code)]` where they are declared). Code that needs a C call uses those wrappers; a new wrapper module is for a new native library only.
- Larger redesigns are welcome (for example a grammar-based SecLang front end, a compiled rule plan, a safer embedding API, splitting the workspace), but do them as separate, reviewable steps with the verification below, and say up front what they change.

## Compatibility contract

These are what users, connectors and operators depend on. Keep them unless the owner approves a change:

- **C API and ABI:** every `msc_*` function, its signature, return codes and memory conventions, and the `libmodsecurity.so.3` SONAME.
- **SecLang semantics:** which configurations are accepted or rejected, and what the accepted ones do (rules, phases, actions, operators, variables, transformations, configuration directives, `Include`).
- **Detection behavior:** matches, interventions, `TX`/`MATCHED_VAR*`/capture contents and rule evaluation order.
- **Output formats:** error log lines, audit log formats (native and JSON), and the persistent collection format.
- **Configuration and directives of the nginx connector.**

Not part of the contract: internal Rust APIs, and the wording and columns of SecLang syntax errors (the owner has approved a new parser that reports them differently). Debug log text is not a contract either, but the differential test compares it line by line, so change it only on purpose and explain the resulting differences.

C++ bugs and quirks are part of current behavior. Fixing one is welcome, but as its own change: name the old behavior, the new behavior and the reason in the commit message, add a regression test, and list it under "Intentional deviations from C++" in `MIGRATION.md`. Never change behavior silently as a side effect of a refactor. Opt-in alternatives (cargo features such as `pm-aho-corasick`) are the way to offer a different behavior without changing the default.

## Verification

Run for every change, before committing:

- `cargo fmt --all -- --check`
- `cargo test` (and `--no-default-features` and the opt-in features when the change touches them)
- `cargo clippy --all-targets -- -D warnings` for the default, `--no-default-features` and `--all-features` builds, plus the nginx connector when it is affected
- For any engine change: `test/differential/run.sh` against the C++ library. It must stay identical (outputs with and without the debug log, and the debug log itself, up to the documented differences: UTF-8 rendering, rule line numbers and `\"` in operator parameters, see `MIGRATION.md`).
- For changes to the SecLang parser, the body processors, transformations or operators: the fuzz targets (`fuzz/README.md`), a few minutes each, and the inputs in `fuzz/regressions/`.
- For connector changes and before merging larger work: the OWASP CRS regression suite through nginx (`test/crs/run.sh`). A rare 502 from the test backend on a large POST is a known flake; rerun before treating a failure as real.

Add focused tests for behavior that a change could affect. When replacing an implementation, compare the old and new one directly on generated inputs.

## Benchmarking

Benchmark every change that can affect performance: the request-processing path (rule evaluation, operators, transformations, variables, collections, regex, body processors), rule loading, dependencies and features, the nginx connector, and anything presented as an optimization.

1. **Prerequisites.** A built C++ libmodsecurity v3.0.17 tree (`CPP_TREE`, built with the same optional dependencies) and an OWASP CRS checkout (`CRS_DIR`). For nginx runs, an nginx binary built `--with-compat` (`NGINX_BIN`, `MIME_TYPES`) and the modules to compare. Run on an otherwise idle machine.
2. **Compare against the parent commit, interleaved.** Wall-clock numbers drift by about ±5% between runs on the same build, so build both libraries and alternate them in the same session (at least five rounds), then compare best and median per scenario. A single before/after pair is not evidence. The library scenarios are `upstream`, `corpus_pl1` and `corpus_pl4` (`test/benchmark/run_library.sh` builds the release library and runs them; `summarize.py library` prints the results).
3. **nginx benchmark** for connector changes and before merging performance work: `test/benchmark/run_nginx.sh` with the modules to compare, then `summarize.py nginx`.
4. **Judge the result.** Compare throughput, p50/p99 latency, rule load time and RSS. Differences under about 3% are noise. A regression beyond that in any scenario must be fixed, or justified in the commit message.
5. **Profiling:** `CARGO_PROFILE_RELEASE_DEBUG=line-tables-only cargo build --release -p modsecurity-capi`, then `perf record` on `target/benchmark/bench_rs`; `valgrind --tool=dhat` for allocations. Keep artifacts under `target/`.
6. **Record the numbers** (before → after, per scenario) in the commit message. Rebuild the default release afterwards if the benchmark used non-default features.

## Workflow

- One coherent change per branch and commit series; keep the build and tests green at every commit. Do not push or merge without the owner's go-ahead.
- More than one agent may be working on this repository. Start from the current `master`, check `git log` and `REFACTORING.md` for work in progress, and keep each change to the area it is about.
- Record design changes and their compatibility notes in `REFACTORING.md` and intentional behavior changes in `MIGRATION.md`.
- Make routine decisions independently. Ask the owner before anything that changes the compatibility contract or reorganizes the whole project.
- Report what changed, how it was verified (with numbers), and what was not verified. Do not claim completion if functionality is missing, stubbed or untested.
