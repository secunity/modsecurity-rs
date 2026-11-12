Convert this C++ codebase to Rust while preserving its existing architecture and organization.

The codebase is already well organized. Treat its folder structure, component boundaries, object responsibilities, and separation of concerns as intentional design decisions.

### Preserve the design

- Keep the existing directory hierarchy and component names wherever practical, adapting filenames to Rust conventions.
- Map C++ namespaces to Rust modules and classes to structs/enums with associated implementations, preserving their responsibilities.
- Keep related functionality in the corresponding files and modules. Do not flatten the project, merge unrelated components, or introduce a new architecture.
- Preserve public behavior, algorithms, configuration semantics, file formats, and protocol compatibility.
- Preserve useful comments and documentation, updating references to match the Rust implementation.
- Avoid unrelated cleanup, new features, and speculative abstractions.

### Use idiomatic Rust within that structure

- Translate the design and behavior rather than mechanically translating C++ syntax.
- Use ownership, borrowing, enums, traits, and `Result` where appropriate.
- Preserve interfaces conceptually; adapt signatures where Rust requires a different expression of ownership or errors.
- Use traits for meaningful abstraction or polymorphism, rather than creating a trait for every class.
- Choose ownership based on actual lifetimes and responsibilities. Do not use excessive cloning, `Rc`, `Arc`, or interior mutability merely to bypass borrow-checker difficulties.
- Prefer safe Rust. Introduce `unsafe` only when necessary, documenting the safety invariants.
- Select dependencies conservatively and explain significant additions.
- Preserve binary layouts and ABI requirements explicitly wherever they are part of an external interface.

### Migration workflow

1. Inspect the codebase, build system, dependencies, tests, and entry points.
2. Summarize the architecture and provide a concise mapping from the existing directories and major types to their Rust equivalents.
3. Identify places where C++ features require a different Rust representation, such as inheritance, shared ownership, templates, or pointer-based relationships.
4. Implement the migration incrementally in coherent components, keeping the Rust project buildable at meaningful checkpoints.
5. Port existing tests and add targeted tests for behavior that could change during translation. Where practical, compare the C++ and Rust implementations using the same inputs.
6. Run formatting, compilation, relevant tests, and Clippy. Investigate failures rather than suppressing them without justification.

### Benchmarking changes before committing

Benchmark every change that can affect performance before committing it: anything under `src/` on the request-processing path (rule evaluation, operators, transformations, variables, collections, `utils/regex`, body processors), rule loading (`src/parser/`), dependency or feature changes, `connectors/nginx`, and any change presented as an optimization. Documentation-only and test-only changes are exempt.

1. **Prerequisites.** A built C++ libmodsecurity v3.0.17 tree (`CPP_TREE`, built with the same optional dependencies) and an OWASP CRS checkout (`CRS_DIR`). For nginx runs, an nginx binary built `--with-compat` (`NGINX_BIN`, `MIME_TYPES`) and the modules to compare. Run on an otherwise idle machine: no concurrent cargo builds, test suites or CRS runs.
2. **Baseline.** Measure the parent commit with the same settings (e.g. in a `git worktree` of `HEAD`; the scripts always benchmark the tree they live in). Absolute numbers drift between runs, so compare each build's ratio to the C++ library measured in the same run, not raw numbers across runs.
3. **Library benchmark** (always): `CPP_TREE=… CRS_DIR=… REPS=3 test/benchmark/run_library.sh`, then `python3 test/benchmark/summarize.py library target/benchmark/library_results.txt`. It builds the release library itself (`FEATURES=…` for feature builds) and covers the `upstream`, `corpus_pl1` and `corpus_pl4` scenarios.
4. **nginx benchmark** (for connector changes, and before merging performance work): `NGINX_BIN=… MIME_TYPES=… CRS_DIR=… CPP_MODULE=… RUSTLIB_MODULE=… RUSTCONN_MODULE=target/release/libngx_http_modsecurity_module.so REPS=3 test/benchmark/run_nginx.sh`, then `python3 test/benchmark/summarize.py nginx target/benchmark/nginx_results.txt`. Rebuild the modules being compared first.
5. **Judge the result.** Compare throughput (tx/s, rps), p50/p99 latency, rule load time and RSS for every scenario. Differences under about 3% are noise; rerun if repetitions disagree. A regression beyond that in any scenario must be investigated and fixed, or justified in the commit message, before committing.
6. **Correctness still comes first.** A faster build only counts if behaviour is unchanged: `cargo test`, `cargo clippy --all-targets` (default, `--no-default-features`), `cargo fmt --check`, and for engine changes `test/differential/run.sh`, which must stay identical to C++.
7. **Profiling** (when looking for or explaining a speedup): build with `CARGO_PROFILE_RELEASE_DEBUG=line-tables-only cargo build --release --lib` and use `perf record` on `target/benchmark/bench_rs`; for allocations use `valgrind --tool=dhat`. Keep profiles and other artifacts under `target/` (never commit them).
8. **Record the numbers.** Put the before → after figures (scenario, tx/s, and the ratio to C++) in the commit message. Afterwards, rebuild the default release (`cargo build --release`) if the benchmark used non-default features, so later runs do not pick up a feature build by accident.

Keep the original C++ source available for reference and comparison until the migration is validated. Follow an existing migration layout if one exists; otherwise, place the Rust project in a separate directory that mirrors the original component hierarchy.

Do not stop after producing a plan: proceed with implementation. Make routine decisions independently. If preserving the existing organization becomes impractical, make the smallest necessary adjustment and explain why. Ask for clarification only when a decision materially affects externally visible behavior or requires a substantial architectural change.

At completion, report what was migrated, any structural deviations, verification results, and remaining gaps. Do not claim completion if functionality is missing, stubbed, or untested.