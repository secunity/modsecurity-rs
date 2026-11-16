//! The multipart parser alone, against a recording context: for each of
//! the bodies below, everything the parser reports (variables with their
//! offsets, debug log lines, results, temporary files) must be what
//! `tests/data/multipart.trace` says. That file was written by the parser
//! before its internals were reworked; `UPDATE_TRACE=1 cargo test -p
//! modsecurity-body --test multipart` rewrites it, for a deliberate change.

mod support;

use modsecurity_body::multipart::{self, Uploads};

support::recorder_for!(multipart, trace);

const CT: &[u8] = b"multipart/form-data; boundary=XyZ";

fn save() -> Uploads {
    Uploads { tmp_save_files: Some(true), ..Uploads::default() }
}

/// (name, Content-Type, body, upload settings).
fn cases() -> Vec<(&'static str, Vec<u8>, Vec<u8>, Uploads)> {
    let none = Uploads::default();
    let b = |s: &str| s.replace('\n', "\r\n").into_bytes();
    let lf = |s: &str| s.as_bytes().to_vec();
    let mut cases: Vec<(&'static str, Vec<u8>, Vec<u8>, Uploads)> = vec![
        (
            "two fields",
            CT.to_vec(),
            b(
                "--XyZ\nContent-Disposition: form-data; name=\"a\"\n\none\n--XyZ\nContent-Disposition: form-data; name=\"b\"\n\ntwo\nlines\n--XyZ--\n",
            ),
            none,
        ),
        (
            "a file, not saved",
            CT.to_vec(),
            b(
                "--XyZ\nContent-Disposition: form-data; name=\"f\"; filename=\"x.txt\"\nContent-Type: text/plain\n\nfile body\nsecond line\n--XyZ--\n",
            ),
            none,
        ),
        (
            "a file, saved",
            CT.to_vec(),
            b(
                "--XyZ\nContent-Disposition: form-data; name=\"f\"; filename=\"x.txt\"\nContent-Type: text/plain\n\nfile body\nsecond line\n--XyZ\nContent-Disposition: form-data; name=\"a\"\n\n1\n--XyZ--\n",
            ),
            save(),
        ),
        (
            "a file, kept",
            CT.to_vec(),
            b("--XyZ\nContent-Disposition: form-data; name=\"f\"; filename=\"x.txt\"\n\nkept\n--XyZ--\n"),
            Uploads { keep_files: Some(true), file_mode: 0o600, ..none },
        ),
        (
            "file limit",
            CT.to_vec(),
            b(
                "--XyZ\nContent-Disposition: form-data; name=\"f1\"; filename=\"1\"\n\none\n--XyZ\nContent-Disposition: form-data; name=\"f2\"; filename=\"2\"\n\ntwo\n--XyZ\nContent-Disposition: form-data; name=\"f3\"; filename=\"3\"\n\nthree\n--XyZ--\n",
            ),
            Uploads { file_limit: 1, ..save() },
        ),
        (
            "filename star",
            CT.to_vec(),
            b(
                "--XyZ\nContent-Disposition: form-data; name=\"f\"; filename=\"plain.txt\"; filename*=UTF-8'en'na%C3%AFve%20file.txt\n\nx\n--XyZ--\n",
            ),
            none,
        ),
        (
            "filename star errors",
            CT.to_vec(),
            b(
                "--XyZ\nContent-Disposition: form-data; name=\"a\"; filename*='en'x\n\n1\n--XyZ\nContent-Disposition: form-data; name=\"b\"; filename*=UTF-8'en\n\n2\n--XyZ\nContent-Disposition: form-data; name=\"c\"; filename*=UTF-8''a%2\n\n3\n--XyZ\nContent-Disposition: form-data; name=\"d\"; filename*=UTF-8''a b\n\n4\n--XyZ\nContent-Disposition: form-data; name=\"e\"; filename*=UTF-8''%zz\n\n5\n--XyZ--\n",
            ),
            none,
        ),
        (
            "quoting",
            CT.to_vec(),
            b(
                "--XyZ\nContent-Disposition: form-data; name='single'\n\n1\n--XyZ\nContent-Disposition: form-data; name=bare'quote\n\n2\n--XyZ\nContent-Disposition: form-data; name=\"esc\\\"aped\\\\ \\x\"\n\n3\n--XyZ\nContent-Disposition: form-data; name=\"open\n\n4\n--XyZ\nContent-Disposition: form-data; name=\"a\" x\n\n5\n--XyZ\nContent-Disposition: form-data; name=\"a\"\"\n\n6\n--XyZ--\n",
            ),
            none,
        ),
        (
            "content-disposition errors",
            CT.to_vec(),
            b(
                "--XyZ\nContent-Disposition: attachment; name=\"a\"\n\n1\n--XyZ\nContent-Disposition: form-data name=\"a\"\n\n2\n--XyZ\nContent-Disposition: form-data; \n\n3\n--XyZ\nContent-Disposition: form-data; name\n\n4\n--XyZ\nContent-Disposition: form-data; name \n\n5\n--XyZ\nContent-Disposition: form-data; name x\n\n6\n--XyZ\nContent-Disposition: form-data; name= \n\n7\n--XyZ\nContent-Disposition: form-data; name=\"\n\n8\n--XyZ\nContent-Disposition: form-data; name=\"a\\\n\n9\n--XyZ\nContent-Disposition: form-data; other=\"a\"\n\n10\n--XyZ\nContent-Disposition: form-data; name=\"a\"; name=\"b\"\n\n11\n--XyZ\nContent-Disposition: form-data; name=\"a\"; filename=\"b\"; filename=\"c\"\n\n12\n--XyZ\nContent-Disposition: form-data; name=\"a\"; filename*=u''b; filename*=u''c\n\n13\n--XyZ\nContent-Disposition: form-data\n\n14\n--XyZ\nContent-Disposition: form-data; filename=\"only\"\n\n15\n--XyZ--\n",
            ),
            none,
        ),
        (
            "part header errors",
            CT.to_vec(),
            b(
                "--XyZ\nno colon here\nContent-Disposition: form-data; name=\"a\"\n\n1\n--XyZ\n: no name\nContent-Disposition: form-data; name=\"b\"\n\n2\n--XyZ\nBad Name: x\nContent-Disposition: form-data; name=\"c\"\n\n3\n--XyZ\nContent-Disposition: form-data; name=\"d\"\nContent-Disposition: form-data; name=\"e\"\n\n4\n--XyZ\nX-Other: 1\n\n5\n--XyZ\n folded first\nContent-Disposition: form-data; name=\"f\"\n\n6\n--XyZ--\n",
            ),
            none,
        ),
        (
            "header folding",
            CT.to_vec(),
            b(
                "--XyZ\nContent-Disposition: form-data;\n name=\"a\"\nX-Long: one\n\ttwo\n \t three\n\n1\n--XyZ\nContent-Disposition: form-data;\n\x0b name=\"b\"\n\n2\n--XyZ--\n",
            ),
            none,
        ),
        (
            "lf lines",
            CT.to_vec(),
            lf(
                "--XyZ\nContent-Disposition: form-data; name=\"a\"\n\none\n--XyZ\nContent-Disposition: form-data; name=\"b\"\n\ntwo\n--XyZ--\n",
            ),
            none,
        ),
        (
            "mixed line endings",
            CT.to_vec(),
            lf(
                "--XyZ\r\nContent-Disposition: form-data; name=\"a\"\n\r\none\n--XyZ\r\nContent-Disposition: form-data; name=\"b\"\r\n\r\ntwo\r\n--XyZ--",
            ),
            none,
        ),
        (
            "final boundary without line end",
            CT.to_vec(),
            lf("--XyZ\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\none\r\n--XyZ--"),
            none,
        ),
        (
            "final boundary where data should begin",
            CT.to_vec(),
            lf("--XyZ\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n--XyZ--"),
            none,
        ),
        (
            "boundary where data should begin",
            CT.to_vec(),
            b("--XyZ\nContent-Disposition: form-data; name=\"a\"\n\n--XyZ\nmore\n--XyZ--\n"),
            none,
        ),
        ("final boundary missing", CT.to_vec(), b("--XyZ\nContent-Disposition: form-data; name=\"a\"\n\none\n"), none),
        ("no boundaries", CT.to_vec(), b("just some text\nand more\n"), none),
        (
            "data before and after",
            CT.to_vec(),
            b("preamble\n--XyZ\nContent-Disposition: form-data; name=\"a\"\n\none\n--XyZ--\nepilogue\n"),
            none,
        ),
        (
            "unmatched and odd boundaries",
            CT.to_vec(),
            b(
                "--XyZ\nContent-Disposition: form-data; name=\"a\"\n\n--other\ntext --XyZ inside\n--Xy\n--XyZ\nContent-Disposition: form-data; name=\"b\"\n\n2\n--XyZ--\n",
            ),
            none,
        ),
        (
            "boundary with trailing text",
            CT.to_vec(),
            b("--XyZ\nContent-Disposition: form-data; name=\"a\"\n\n1\n--XyZtail\n"),
            none,
        ),
        (
            "boundary after whitespace",
            CT.to_vec(),
            b("-- XyZ\nContent-Disposition: form-data; name=\"a\"\n\n1\n--XyZ--\n"),
            none,
        ),
        (
            "duplicate final boundary",
            CT.to_vec(),
            lf("--XyZ\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--XyZ--\r\n--XyZ--\r\n"),
            none,
        ),
        (
            "nul bytes",
            CT.to_vec(),
            lf(
                "--XyZ\r\nContent-Disposition: form-data; name=\"a\"\r\nX-Nul: a\0b\r\n\r\nva\0lue\r\n--XyZ\r\nContent-Disposition: form-data; name=\"b\"\r\n\r\n--\0XyZ\r\n--XyZ\0\r\n--XyZ--\r\n",
            ),
            none,
        ),
        (
            "quoted boundary",
            b"multipart/form-data; boundary=\"XyZ\"".to_vec(),
            b("--\"XyZ\"\nContent-Disposition: form-data; name=\"a\"\n\n1\n--XyZ--\n"),
            none,
        ),
        (
            "quoted boundary, used",
            b"multipart/form-data; boundary=\"XyZ\"".to_vec(),
            b("--XyZ\nContent-Disposition: form-data; name=\"a\"\n\n1\n--XyZ--\n"),
            none,
        ),
        (
            "boundary with a parameter after it",
            b"multipart/form-data; boundary=XyZ; charset=UTF-8".to_vec(),
            b("--XyZ\nContent-Disposition: form-data; name=\"a\"\n\n1\n--XyZ--\n"),
            none,
        ),
        (
            "empty value and empty lines",
            CT.to_vec(),
            b(
                "--XyZ\nContent-Disposition: form-data; name=\"a\"\n\n\n--XyZ\nContent-Disposition: form-data; name=\"b\"\n\n\n\n\n--XyZ--\n",
            ),
            none,
        ),
    ];

    // Lines longer than the parser's buffer: in a value, in a saved file
    // (with a carriage return at the buffer's end), and in a header.
    let long = "v".repeat(5000);
    cases.push((
        "long value",
        CT.to_vec(),
        b(&format!("--XyZ\nContent-Disposition: form-data; name=\"a\"\n\n{long}\nshort\n--XyZ--\n")),
        none,
    ));
    let mut file = b("--XyZ\nContent-Disposition: form-data; name=\"f\"; filename=\"big\"\n\n");
    file.extend(std::iter::repeat_n(b'x', 4095));
    file.extend_from_slice(b"\r\nrest\r\r\n\nend\r\n--XyZ--\r\n");
    cases.push(("long file line", CT.to_vec(), file, save()));
    cases.push((
        "long header",
        CT.to_vec(),
        b(&format!("--XyZ\nContent-Disposition: form-data; name=\"{long}\"\n\n1\n--XyZ--\n")),
        none,
    ));
    let folded = format!(" {}\n", "f".repeat(1500)).repeat(3);
    cases.push((
        "folded header too long",
        CT.to_vec(),
        b(&format!("--XyZ\nContent-Disposition: form-data; name=\"a\"\nX-Long: 1\n{folded}\n1\n--XyZ--\n")),
        none,
    ));

    // Content-Type headers the parser refuses or flags.
    let body = b("--XyZ\nContent-Disposition: form-data; name=\"a\"\n\n1\n--XyZ--\n");
    for (name, header) in [
        ("header: empty", &b""[..]),
        ("header: other type", b"text/plain; boundary=XyZ"),
        ("header: no boundary", b"multipart/form-data"),
        ("header: upper case boundary", b"multipart/form-data; BOUNDARY=XyZ"),
        ("header: two boundaries", b"multipart/form-data; boundary=XyZ; boundary=abc"),
        ("header: no semicolon", b"multipart/form-data boundary=XyZ"),
        ("header: text before boundary", b"multipart/form-data; x boundary=XyZ"),
        ("header: no equals sign", b"multipart/form-data; boundary"),
        ("header: whitespace around the equals sign", b"multipart/form-data; boundary = XyZ"),
        ("header: text after the name", b"multipart/form-data; boundaryx=XyZ"),
        ("header: half quoted", b"multipart/form-data; boundary=\"XyZ"),
        ("header: empty quoted", b"multipart/form-data; boundary=\"\""),
        ("header: empty", b"multipart/form-data; boundary="),
        ("header: boundary in the boundary", b"multipart/form-data; boundary=aBoundary=b"),
        ("header: invalid characters", b"multipart/form-data; boundary=Xy{Z"),
        ("header: nul byte", b"multipart/form-data; boundary=XyZ\0abc"),
        ("header: mixed case type", b"MultiPart/Form-Data; boundary=XyZ"),
    ] {
        cases.push((name, header.to_vec(), body.clone(), none));
    }
    cases.push((
        "header: too long",
        format!("multipart/form-data; boundary={}", "b".repeat(1024)).into_bytes(),
        body,
        none,
    ));
    cases
}

#[test]
fn traces() {
    let mut text = String::new();
    for (name, header, body, uploads) in cases() {
        text.push_str(&format!("=== {name}\n{}", trace(&header, &body, usize::MAX, uploads)));
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
