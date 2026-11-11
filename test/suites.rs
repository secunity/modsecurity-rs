//! `cargo test` entry point for the ported C++ test suites (the equivalent
//! of `make check`): runs the `regression_tests` and `unit_tests` utilities
//! from the `test/` directory, as the C++ build does.

use std::process::Command;

fn run(bin: &str, args: &[&str]) -> (i32, String) {
    let out = Command::new(bin)
        .args(args)
        .current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/test"))
        .output()
        .expect("run test utility");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    (out.status.code().unwrap_or(-1), stdout)
}

/// The regression suite must pass completely (skips are fine: they are the
/// tests needing optional features that are not compiled in).
#[test]
fn regression_suite() {
    let (code, out) = run(env!("CARGO_BIN_EXE_regression_tests"), &[]);
    let summary = out.lines().rev().find(|l| l.contains("Ran a total of")).unwrap_or("").to_string();
    assert_eq!(code, 0, "regression failures: {}\n{}", summary, out);
}

/// Operator and transformation unit tests. The C++ reference build fails
/// exactly 11 of them, all in `phpArgsNames.json` (a transformation that does
/// not exist in libmodsecurity, so the value is returned unchanged); the
/// Rust port must fail the same set and nothing else.
#[test]
fn unit_suite() {
    let (code, out) = run(env!("CARGO_BIN_EXE_unit_tests"), &[]);
    let failing_files: Vec<&str> =
        out.lines().filter(|l| l.contains("tests failed.") && !l.contains("\x1B[32m0 tests failed.")).collect();
    assert_eq!(code, 11, "unit failures: {:?}\n{}", failing_files, out);
    assert!(
        failing_files.len() == 1 && failing_files[0].contains("phpArgsNames.json"),
        "unexpected failing files: {:?}",
        failing_files
    );
}
