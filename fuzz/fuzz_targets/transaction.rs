//! Runs arbitrary requests and responses through a fixed rule set that
//! applies every transformation and the input-sensitive operators to every
//! part of the transaction, with the URL-encoded, JSON, XML and multipart
//! body processors.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use modsecurity::ModSecurity;
use modsecurity::RulesSet;
use modsecurity::Transaction;

const TRANSFORMATIONS: &[&str] = &[
    "base64Decode", "base64DecodeExt", "base64Encode", "cmdLine", "compressWhitespace", "cssDecode",
    "escapeSeqDecode", "hexDecode", "hexEncode", "htmlEntityDecode", "jsDecode", "length", "lowercase", "md5",
    "normalisePath", "normalisePathWin", "parityEven7bit", "parityOdd7bit", "parityZero7bit", "removeComments",
    "removeCommentsChar", "removeNulls", "removeWhitespace", "replaceComments", "replaceNulls", "sha1",
    "sqlHexDecode", "trim", "trimLeft", "trimRight", "uppercase", "urlDecode", "urlDecodeUni", "urlEncode",
    "utf8toUnicode",
];

const OPERATORS: &[&str] = &[
    "@detectSQLi", "@detectXSS", "@validateUrlEncoding", "@validateUtf8Encoding", "@validateByteRange 1-9,11-255",
    "@pm select union <script", "@contains a", "@containsWord a", "@beginsWith a", "@endsWith a", "@streq a",
    "@strmatch ab", "@within abc", "@eq 1", "@gt 1", "@verifyCC \\d{13,16}", "@verifyCPF \\d{11}",
    "@verifySSN \\d{9}", "@verifySVNR \\d{10}", "@ipMatch 10.0.0.0/8,::1", "@rx (?i)(a+)(b*)",
];

/// Every request variable with values from the input.
const TARGETS: &str = "ARGS|ARGS_NAMES|REQUEST_HEADERS|REQUEST_HEADERS_NAMES|REQUEST_COOKIES|REQUEST_COOKIES_NAMES|\
REQUEST_URI|REQUEST_URI_RAW|REQUEST_FILENAME|REQUEST_BASENAME|QUERY_STRING|REQUEST_LINE|REQUEST_BODY|XML:/*|\
FILES|FILES_NAMES|MULTIPART_PART_HEADERS|MULTIPART_NAME|MULTIPART_FILENAME|PATH_INFO";

fn rules() -> String {
    let mut r = String::from(
        "SecRuleEngine On\n\
         SecRequestBodyAccess On\n\
         SecResponseBodyAccess On\n\
         SecResponseBodyMimeType text/plain text/html application/json\n\
         SecRequestBodyLimit 65536\n\
         SecRequestBodyNoFilesLimit 65536\n\
         SecArgumentsLimit 200\n\
         SecRequestBodyJsonDepthLimit 32\n\
         SecPcreMatchLimit 5000\n\
         SecRule REQUEST_HEADERS:Content-Type \"@rx (?i)^application/json\" \"id:1,phase:1,pass,nolog,ctl:requestBodyProcessor=JSON\"\n\
         SecRule REQUEST_HEADERS:Content-Type \"@rx (?i)xml\" \"id:2,phase:1,pass,nolog,ctl:requestBodyProcessor=XML\"\n",
    );
    let mut id = 100;
    for t in TRANSFORMATIONS {
        id += 1;
        r.push_str(&format!("SecRule {TARGETS} \"@rx ^(?:a|<)\" \"id:{id},phase:2,pass,log,t:none,t:{t}\"\n"));
    }
    for o in OPERATORS {
        id += 1;
        r.push_str(&format!("SecRule {TARGETS} \"{o}\" \"id:{id},phase:2,pass,log,capture,t:none,t:urlDecodeUni\"\n"));
    }
    r.push_str(
        "SecRule ARGS \"@rx (a)(b)?\" \"id:300,phase:2,pass,capture,setvar:'tx.%{tx.1}=%{matched_var}',\
         msg:'%{MATCHED_VAR_NAME}',logdata:'%{tx.0}',setvar:tx.score=+1\"\n\
         SecRule REQBODY_ERROR|MULTIPART_STRICT_ERROR|MULTIPART_UNMATCHED_BOUNDARY|REQBODY_PROCESSOR_ERROR \"!@eq 0\" \
         \"id:301,phase:2,pass,log,msg:'%{REQBODY_ERROR_MSG}'\"\n\
         SecRule &ARGS \"@gt 1\" \"id:302,phase:2,pass,chain\"\n\
         SecRule ARGS_NAMES \"@rx .\" \"setvar:tx.n=%{matched_var}\"\n\
         SecRule RESPONSE_HEADERS|RESPONSE_BODY|RESPONSE_STATUS \"@rx (?i)(error|<script)\" \
         \"id:400,phase:4,pass,log,t:none,t:htmlEntityDecode,t:lowercase\"\n\
         SecRule TX:score \"@gt 3\" \"id:401,phase:5,pass,log,msg:'score %{tx.score}'\"\n",
    );
    r
}

/// How the request body is sent.
#[derive(Arbitrary, Debug)]
enum Body {
    UrlEncoded(Vec<u8>),
    Json(Vec<u8>),
    Xml(Vec<u8>),
    /// A multipart body with the boundary `XyZ`.
    Multipart(Vec<u8>),
    Other(Vec<u8>, Vec<u8>),
}

#[derive(Arbitrary, Debug)]
struct Exchange {
    method: Vec<u8>,
    uri: Vec<u8>,
    headers: Vec<(Vec<u8>, Vec<u8>)>,
    body: Body,
    status: u16,
    response_headers: Vec<(Vec<u8>, Vec<u8>)>,
    response_body: Vec<u8>,
}

thread_local! {
    static ENGINE: &'static (ModSecurity, RulesSet) = {
        let mut ms = ModSecurity::new();
        ms.set_server_log_cb(Box::new(|_, _| {}));
        let mut set = RulesSet::new();
        set.load(&rules()).expect("the fuzz rules load");
        Box::leak(Box::new((ms, set)))
    };
}

fuzz_target!(|x: Exchange| {
    ENGINE.with(|engine| {
        let (ms, rules) = *engine;
        let mut t = Transaction::new(ms, rules, None);
        t.process_connection("10.0.0.7", 12345, "10.0.0.1", 80);
        t.process_uri(&x.uri, &x.method, b"1.1");
        let (content_type, body): (&[u8], &[u8]) = match &x.body {
            Body::UrlEncoded(b) => (b"application/x-www-form-urlencoded", b),
            Body::Json(b) => (b"application/json", b),
            Body::Xml(b) => (b"text/xml", b),
            Body::Multipart(b) => (b"multipart/form-data; boundary=XyZ", b),
            Body::Other(c, b) => (c, b),
        };
        t.add_request_header(b"Content-Type", content_type);
        for (k, v) in &x.headers {
            t.add_request_header(k, v);
        }
        t.process_request_headers();
        let _ = t.intervention();
        t.append_request_body(body);
        t.process_request_body();
        let _ = t.intervention();
        for (k, v) in &x.response_headers {
            t.add_response_header(k, v);
        }
        t.add_response_header(b"Content-Type", b"text/html");
        t.process_response_headers(i32::from(x.status), "HTTP/1.1");
        t.append_response_body(&x.response_body);
        t.process_response_body();
        let _ = t.intervention();
        t.process_logging();
    });
});
