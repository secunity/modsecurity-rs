# Fuzzing

libFuzzer targets for [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz)
(nightly Rust, `cargo install cargo-fuzz`). This directory is its own
workspace.

| Target | Input | Exercises |
|---|---|---|
| `seclang` | a configuration | the SecLang grammar and every directive, operator and action constructor |
| `transaction` | a request and response (`arbitrary`) | URI, header and cookie parsing, every transformation and the input-sensitive operators on every request variable, macros and `setvar`, response inspection, logging |
| `body` | a request body | the URL-encoded, JSON, XML (also parsed into `ARGS`) and multipart body processors, with the body appended in pieces |

`seclang` skips configurations that would read or write files or use the
network when loaded (`Include`, `SecRemoteRules`, logs, `...FromFile`,
scripts, DTD/schema validation, ...): the fuzzer must not write files or
make requests.

## Running

```sh
cd fuzz
cargo +nightly fuzz run -O seclang -- -fork=3 -max_total_time=900
cargo +nightly fuzz run -O transaction -- -dict=transaction.dict -fork=3 -max_total_time=900
cargo +nightly fuzz run -O body -- -dict=transaction.dict -fork=3 -max_total_time=900
```

Add `-ignore_crashes=1 -ignore_timeouts=1 -ignore_ooms=1` to keep going
after a finding; findings are written to `artifacts/<target>/` and replayed
with `cargo +nightly fuzz run -O <target> artifacts/<target>/<file>`.

Inputs that found bugs are kept in `regressions/<target>/`; replay them
after changing the code they exercise:
`cargo +nightly fuzz run -O <target> regressions/<target>/*`.

Seeds: the corpus directories (`corpus/<target>/`, not versioned) start
empty. Useful seeds are the statements of OWASP CRS and of the regression
tests for `seclang`, and the request bodies of the regression tests (with
the kind byte and a piece size in front, and the multipart boundary
rewritten to `XyZ`) for `body`.

`cargo +nightly fuzz coverage <target>` and `llvm-cov report` (from the
nightly `llvm-tools` component) show what a corpus reaches.
