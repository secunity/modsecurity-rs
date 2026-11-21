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

/// A carriage return that does not fit in a full buffer is looked at again
/// with the next one, and counted once: the offsets after it are where the
/// data is in the body.
#[test]
fn offsets_after_a_held_back_carriage_return() {
    let (_, header, body, uploads) = cases().into_iter().find(|(name, ..)| *name == "long file line").unwrap();
    let start = body.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let size = body.len() - start - b"\r\n--XyZ--\r\n".len();
    let trace = trace(&header, &body, usize::MAX, uploads, false);
    let line = format!("add FilesSizes f = {size} @{}+{size}", 2000 + start);
    assert!(trace.lines().any(|l| l == line), "{line}");
}

/// A body given one byte at a time gives the same variables, results and
/// files as given whole (the debug log differs: it shows the pieces of
/// data as they are added). Data after the final boundary in a later piece
/// is data after it, as in the same piece.
#[test]
fn one_byte_at_a_time() {
    let without_debug_log =
        |trace: &str| trace.lines().filter(|line| !line.starts_with("debug[")).map(String::from).collect::<Vec<_>>();
    for (name, header, body, uploads) in cases() {
        let broken = name == "broken upload directory";
        let whole = without_debug_log(&trace(&header, &body, usize::MAX, uploads, broken));
        let bytes = without_debug_log(&trace(&header, &body, 1, uploads, broken));
        for (got, want) in bytes.iter().zip(&whole) {
            assert_eq!(got, want, "{name}");
        }
        assert_eq!(bytes.len(), whole.len(), "{name}");
    }
}
