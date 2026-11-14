//! Request bodies: the first byte picks the body processor (URL-encoded,
//! JSON, XML, multipart with the boundary `XyZ`, XML parsed into `ARGS`),
//! the rest is the body,
//! appended in pieces of the size the second byte gives.

#![no_main]

use libfuzzer_sys::fuzz_target;
use modsecurity::ModSecurity;
use modsecurity::RulesSet;
use modsecurity::Transaction;

const RULES: &str = "SecRuleEngine On
SecRequestBodyAccess On
SecRequestBodyLimit 131072
SecRequestBodyNoFilesLimit 131072
SecArgumentsLimit 500
SecRequestBodyJsonDepthLimit 64
SecRule REQUEST_HEADERS:Content-Type \"@rx (?i)^application/json\" \"id:1,phase:1,pass,nolog,ctl:requestBodyProcessor=JSON\"
SecRule REQUEST_HEADERS:Content-Type \"@rx (?i)^text/xml\" \"id:2,phase:1,pass,nolog,ctl:requestBodyProcessor=XML\"
SecRule REQUEST_HEADERS:Content-Type \"@rx (?i)^application/xml\" \"id:6,phase:1,pass,nolog,ctl:requestBodyProcessor=XML,ctl:parseXmlIntoArgs=On\"
SecRule ARGS|ARGS_NAMES|XML:/*|XML://@*|FILES|FILES_NAMES|FILES_SIZES|MULTIPART_PART_HEADERS|MULTIPART_NAME|MULTIPART_FILENAME|REQUEST_BODY \"@rx .\" \"id:3,phase:2,pass,log,t:none\"
SecRule REQBODY_ERROR|REQBODY_PROCESSOR_ERROR|MULTIPART_STRICT_ERROR|MULTIPART_UNMATCHED_BOUNDARY|MULTIPART_BOUNDARY_QUOTED|MULTIPART_BOUNDARY_WHITESPACE|MULTIPART_DATA_BEFORE|MULTIPART_DATA_AFTER|MULTIPART_HEADER_FOLDING|MULTIPART_LF_LINE|MULTIPART_MISSING_SEMICOLON|MULTIPART_INVALID_QUOTING|MULTIPART_INVALID_PART|MULTIPART_INVALID_HEADER_FOLDING|MULTIPART_FILE_LIMIT_EXCEEDED|MULTIPART_CRLF_LF_LINES \"!@eq 0\" \"id:4,phase:2,pass,log,msg:'%{REQBODY_ERROR_MSG}'\"
SecRule &ARGS \"@gt 0\" \"id:5,phase:2,pass,log\"
";

const CONTENT_TYPES: &[&[u8]] = &[
    b"application/x-www-form-urlencoded",
    b"application/json",
    b"text/xml",
    b"multipart/form-data; boundary=XyZ",
    // XML, also parsed into ARGS.
    b"application/xml",
];

thread_local! {
    static ENGINE: &'static (ModSecurity, RulesSet) = {
        let mut ms = ModSecurity::new();
        ms.set_server_log_cb(Box::new(|_, _| {}));
        let mut set = RulesSet::new();
        set.load(RULES).expect("the fuzz rules load");
        Box::leak(Box::new((ms, set)))
    };
}

fuzz_target!(|data: &[u8]| {
    let [kind, piece, body @ ..] = data else { return };
    let content_type = CONTENT_TYPES[usize::from(*kind) % CONTENT_TYPES.len()];
    let piece = usize::from(*piece).max(1);
    ENGINE.with(|engine| {
        let (ms, rules) = *engine;
        let mut t = Transaction::new(ms, rules, None);
        t.process_connection("10.0.0.7", 12345, "10.0.0.1", 80);
        t.process_uri(b"/upload", b"POST", b"1.1");
        t.add_request_header(b"Content-Type", content_type);
        t.add_request_header(b"Content-Length", body.len().to_string().as_bytes());
        t.process_request_headers();
        for chunk in body.chunks(piece) {
            t.append_request_body(chunk);
        }
        t.process_request_body();
        let _ = t.intervention();
        t.process_logging();
    });
});
