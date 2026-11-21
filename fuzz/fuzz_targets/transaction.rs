//! Runs arbitrary requests and responses through a fixed rule set that
//! applies every transformation and the input-sensitive operators to every
//! part of the transaction, with the URL-encoded, JSON, XML and multipart
//! body processors; persistent collections, `ctl:` actions and disruptive
//! actions driven by the input; and the audit log (native, or JSON with the
//! debug log at level 9), written to `/dev/null`.
//!
//! Not covered: `request_body_from_file` (it would read a path from the
//! input) and the concurrent audit log (it writes a file per entry).

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

fn rules(json_audit_log: bool) -> String {
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
         SecAuditEngine On\n\
         SecAuditLogType Serial\n\
         SecAuditLog /dev/null\n\
         SecAuditLogParts ABCDEFGHIJKZ\n\
         SecAuditLogRelevantStatus \"^(?:5|4(?!04))\"\n\
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
    // The level 9 debug log costs about 3x the run time: only in one set.
    if json_audit_log {
        r.push_str("SecAuditLogFormat JSON\nSecDebugLog /dev/null\nSecDebugLogLevel 9\n");
    }
    r.push_str(&format!("SecUnicodeMapFile {}/../unicode.mapping 20127\n", env!("CARGO_MANIFEST_DIR")));
    // Persistent collections. The keys come from a small set, so the
    // in-memory collections do not grow from one run to the next.
    r.push_str(
        "SecAction \"id:10,phase:1,pass,nolog,initcol:global=global,initcol:ip=%{REMOTE_ADDR}\"\n\
         SecRule REQUEST_COOKIES:sid \"@rx ^[a-c]{1,2}$\" \"id:11,phase:1,pass,nolog,setsid:%{matched_var},\
         setvar:session.hits=+1,expirevar:session.hits=1,setvar:ip.score=+%{session.hits}\"\n\
         SecRule REQUEST_COOKIES:uid \"@rx ^[a-c]$\" \"id:12,phase:1,pass,nolog,setuid:%{matched_var},\
         setvar:user.seen=1,setvar:ip.score=-1,setvar:global.n=+1\"\n\
         SecRule IP:SCORE|SESSION:HITS|USER|GLOBAL:N \"@gt 2\" \"id:13,phase:2,pass,log,msg:'%{matched_var_name}'\"\n",
    );
    // ctl: actions chosen by the input (the argument `ctl`).
    let ctls = [
        "ruleRemoveById=101-130",
        "ruleRemoveById=300",
        "ruleRemoveByTag=t1",
        "ruleRemoveTargetById=110;ARGS:a",
        "ruleRemoveTargetByTag=t1;REQUEST_HEADERS",
        "ruleEngine=DetectionOnly",
        "ruleEngine=Off",
        "auditEngine=Off",
        "auditEngine=RelevantOnly",
        "auditLogParts=+E",
        "requestBodyAccess=Off",
        "forceRequestBodyVariable=On",
        "requestBodyProcessor=URLENCODED",
        "requestBodyProcessor=JSON",
    ];
    for (i, c) in ctls.iter().enumerate() {
        r.push_str(&format!(
            "SecRule ARGS_GET:ctl \"@streq {i}\" \"id:{},phase:1,pass,nolog,tag:t1,ctl:{c}\"\n",
            20 + i
        ));
    }
    // Disruptive actions with macros, chosen by the argument `do`.
    r.push_str(
        "SecRule ARGS:do \"@streq deny\" \"id:50,phase:2,deny,status:403,msg:'%{ARGS.do}'\"\n\
         SecRule ARGS:do \"@streq redirect\" \"id:51,phase:2,redirect:'http://example.com/%{ARGS.to}'\"\n\
         SecRule ARGS:do \"@streq drop\" \"id:52,phase:2,drop\"\n\
         SecRule ARGS:do \"@streq allow\" \"id:53,phase:1,allow:request\"\n\
         SecRule ARGS:do \"@streq skip\" \"id:54,phase:2,pass,skipAfter:END\"\n\
         SecRule ARGS \"@rx a\" \"id:55,phase:2,pass,log,tag:t1,multiMatch,t:none,t:lowercase,t:urlDecodeUni\"\n\
         SecMarker END\n",
    );
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
    /// Whether the rule set with the JSON audit log and the debug log runs
    /// (or the one with the native audit log).
    json_audit_log: bool,
    method: Vec<u8>,
    uri: Vec<u8>,
    headers: Vec<(Vec<u8>, Vec<u8>)>,
    body: Body,
    status: u16,
    response_headers: Vec<(Vec<u8>, Vec<u8>)>,
    response_body: Vec<u8>,
}

thread_local! {
    /// The engine, and the rule sets with the native and the JSON audit log.
    static ENGINE: &'static (ModSecurity, [RulesSet; 2]) = {
        let mut ms = ModSecurity::new();
        ms.set_server_log_cb(Box::new(|_, _| {}));
        let sets = [false, true].map(|json| {
            let mut set = RulesSet::new();
            set.load(&rules(json)).expect("the fuzz rules load");
            set
        });
        Box::leak(Box::new((ms, sets)))
    };
}

fuzz_target!(|x: Exchange| {
    ENGINE.with(|engine| {
        let (ms, sets) = *engine;
        let mut t = Transaction::new(ms, &sets[usize::from(x.json_audit_log)], None);
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
        t.process_response_headers(u16::from(x.status), "HTTP/1.1");
        t.append_response_body(&x.response_body);
        t.process_response_body();
        let _ = t.intervention();
        t.process_logging();
    });
});
