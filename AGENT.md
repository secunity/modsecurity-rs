This repository is a Rust implementation of libmodsecurity v3 (the ModSecurity web application firewall engine), with an nginx connector in `connectors/nginx`. It started as a port of the C++ library v3.0.17. It is now its own engine: the C++ code base is a reference to consult, not a behavior to reproduce.

## Design freedom

- Design for Rust, not for the C++ layout. Module boundaries, type hierarchies, file organization, internal APIs and data representations may be redesigned when that makes the code clearer, safer, faster or easier to maintain. There is no need to keep a file per C++ header, C++ class names, or "Port of ..." structure.
- Prefer well-maintained crates over hand-written code when they do the job. Before replacing an implementation, confirm the crate has the same semantics on the inputs that matter (compare both on generated inputs), and record the reason for each new dependency in `Cargo.toml`.
- Prefer safe Rust. Keep `unsafe` at the boundaries with a `SAFETY` comment on every block: the C API is the `modsecurity-capi` crate and the native libraries are wrapped by the `modsecurity-native` crate (`crates/`); the engine crate (`modsecurity`, at the root) forbids `unsafe_code`. Code that needs a C call uses a safe function of `modsecurity-native`; a new module there is for a new native library only. C functions that tests compare with go in its `testing` module.
- Larger redesigns are welcome (for example a grammar-based SecLang front end, a compiled rule plan, a safer embedding API, splitting the workspace), but do them as separate, reviewable steps with the verification below, and say up front what they change.

## What must hold

The bar for behavior is the tests, not the C++ library:

- **The test suites of the original ModSecurity pass:** the regression suite and the unit suite (`cargo test` runs both, `test/suites.rs`).
- **The OWASP CRS regression suite passes** through nginx (`test/crs/run.sh`).
- **The interfaces other software is built against stay:** the C API and ABI (every `msc_*` function, its signature, return codes and memory conventions, and the `libmodsecurity.so.3` SONAME), and the configuration directives of the nginx connector. Changing these needs the owner's approval.

Everything else may change when the result is a better engine: internal data structures and evaluation strategy, the order in which a collection's entries are visited, parsing of malformed input, error and debug log wording, and behavior that only exists because of how the C++ code happened to be written. Do not keep a C++ accident for its own sake, and do not ask before removing one that no test depends on. When a test does depend on one, keep exactly what the test needs and say so in a comment.

Behavior changes are still made on purpose and in the open: each is its own commit that names the old behavior, the new behavior and the reason, comes with a regression test, and is listed under "Intentional deviations from C++" in `MIGRATION.md`. Never change behavior silently as a side effect of a refactor. Changes that weaken detection (a request that was blocked is no longer blocked, a value a rule could see is hidden) need the owner's approval even when every test passes.

## Verification

Run for every change, before committing:

- `cargo fmt --all -- --check`
- `cargo test` (and `--no-default-features` and the opt-in features when the change touches them)
- `cargo clippy --all-targets -- -D warnings` for the default, `--no-default-features` and `--all-features` builds, plus the nginx connector when it is affected
- (`.github/workflows/ci.yml` runs the three checks above on every push and pull request; the ones below are run by hand.)
- For any engine change: `test/differential/run.sh` against the C++ library, as a report and not a gate. It shows what a change did to the outputs and the debug log on CRS traffic. A refactor that claims to change no behavior must leave it identical; a behavior change must explain every difference it shows (in the commit message), and a difference in an intervention is a detection change.
- For changes to the SecLang parser, the body processors, transformations or operators: the fuzz targets (`fuzz/README.md`), a few minutes each, and the inputs in `fuzz/regressions/`.
- For connector changes, for every behavior change and before merging larger work: the OWASP CRS regression suite through nginx (`test/crs/run.sh`). The script reruns tests that failed, alone, up to three times (`RETRIES`), because the test backend sometimes drops a large POST and nginx answers 502 (test 920390-1); a test that fails every time is a real failure.

Add focused tests for behavior that a change could affect. When replacing an implementation, compare the old and new one directly on generated inputs.

## Benchmarking

Benchmark every change that can affect performance: the request-processing path (rule evaluation, operators, transformations, variables, collections, regex, body processors), rule loading, dependencies and features, the nginx connector, and anything presented as an optimization.

1. **Prerequisites.** A built C++ libmodsecurity v3.0.17 tree (`CPP_TREE`, built with the same optional dependencies) and an OWASP CRS checkout (`CRS_DIR`). For nginx runs, an nginx binary built `--with-compat` (`NGINX_BIN`, `MIME_TYPES`) and the modules to compare. Run on an otherwise idle machine.
2. **Compare against the parent commit, interleaved.** Wall-clock numbers drift by about ±5% between runs on the same build, so build both libraries and alternate them in the same session (at least five rounds), then compare best and median per scenario. A single before/after pair is not evidence. The library scenarios are `upstream`, `corpus_pl1` and `corpus_pl4`: `test/benchmark/build_variant.sh NAME [REV]` builds the release library of a commit (e.g. `parent HEAD~1`, `candidate`, and `control HEAD~1` as an A/A check of the noise), and `VARIANTS="parent candidate control" test/benchmark/run_library.sh` runs them interleaved and prints best and median per scenario.
3. **nginx benchmark** for connector changes and before merging performance work: `test/benchmark/run_nginx.sh` with the modules to compare (it fails when a response has an unexpected status, which would mean the run did not measure what it should).
4. **Judge the result.** Compare throughput, p50/p99 latency, rule load time and RSS. Differences under about 3% are noise. A regression beyond that in any scenario must be fixed, or justified in the commit message.
5. **Profiling:** `CARGO_PROFILE_RELEASE_DEBUG=line-tables-only cargo build --release -p modsecurity-capi`, then `perf record` on `target/benchmark/bench_rs`; `valgrind --tool=dhat` for allocations. Keep artifacts under `target/`.
6. **Record the numbers** (before → after, per scenario) in the commit message. Rebuild the default release afterwards if the benchmark used non-default features.

## Workflow

- One coherent change per branch and commit series; keep the build and tests green at every commit. Do not push or merge without the owner's go-ahead.
- More than one agent may be working on this repository. Start from the current `master`, check `git log` and `REFACTORING.md` for work in progress, and keep each change to the area it is about.
- Record design changes and their compatibility notes in `REFACTORING.md` and intentional behavior changes in `MIGRATION.md`.
- Make routine decisions independently. Ask the owner before anything that changes the compatibility contract or reorganizes the whole project.
- Report what changed, how it was verified (with numbers), and what was not verified. Do not claim completion if functionality is missing, stubbed or untested.
