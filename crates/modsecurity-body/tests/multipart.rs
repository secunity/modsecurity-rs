//! The multipart parser alone, against a recording context: for each of
//! the bodies below, everything the parser reports (variables with their
//! offsets, debug log lines, results, temporary files) must be what
//! `tests/data/multipart.trace` says. That file was written by the parser
//! before its internals were reworked; `UPDATE_TRACE=1 cargo test -p
//! modsecurity-body --test multipart` rewrites it, for a deliberate change.

mod support;

use modsecurity_body::multipart;
use support::cases;

support::recorder_for!(multipart, trace);

#[test]
fn traces() {
    let mut text = String::new();
    for (name, header, body, uploads) in cases() {
        text.push_str(&format!(
            "=== {name}\n{}",
            trace(&header, &body, usize::MAX, uploads, name == "broken upload directory")
        ));
    }
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/multipart.trace");
    if std::env::var_os("UPDATE_TRACE").is_some() {
        std::fs::write(path, &text).expect("writing the trace");
    }
    let expected = std::fs::read_to_string(path).expect("tests/data/multipart.trace");
    for (n, (got, want)) in text.lines().zip(expected.lines()).enumerate() {
        assert_eq!(got, want, "line {} of the trace", n + 1);
    }
    assert_eq!(text.lines().count(), expected.lines().count(), "length of the trace");
}
