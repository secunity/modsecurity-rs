//! Port of `test/regression/regression.cc` / `regression_test.cc`: runs the
//! SecLang regression test cases (`test/test-cases/regression/*.json`).
//!
//! Usage, from the `test/` directory like the C++ utility:
//! `regression_tests [automake] [path[:N]]` — `path` is a directory or a
//! single JSON file, `:N` selects the N-th file. Exit status: number of
//! failed tests.

#[path = "../common/mod.rs"]
mod common;

use std::sync::{Arc, Mutex};

use common::*;
use modsecurity::intervention::{self, ModSecurityIntervention};
use modsecurity::modsecurity::{MODSECURITY_VERSION, ModSecurity, ServerLogEntry};
use modsecurity::rules_set::RulesSet;
use modsecurity::transaction::Transaction;
use modsecurity::utils::json::JsonValue;
use modsecurity::utils::regex::Regex;

const DEFAULT_TEST_PATH: &str = "test-cases/regression";

#[derive(Default)]
struct RegressionTest {
    filename: String,
    name: String,
    enabled: i64,
    resource: String,
    client_ip: String,
    client_port: i64,
    server_ip: String,
    server_port: i64,
    hostname: String,
    uri: Vec<u8>,
    method: Vec<u8>,
    http_version: Vec<u8>,
    request_headers: Vec<(Vec<u8>, Vec<u8>)>,
    request_body: Vec<u8>,
    response_headers: Vec<(Vec<u8>, Vec<u8>)>,
    response_body: Vec<u8>,
    response_protocol: String,
    audit_log: String,
    debug_log: String,
    error_log: String,
    http_code: i64,
    parser_error: String,
    rules: String,
}

fn array_to_str(v: Option<&JsonValue>) -> Vec<u8> {
    let mut out = Vec::new();
    if let Some(JsonValue::Array(a)) = v {
        for x in a {
            out.extend_from_slice(&json_string(Some(x)));
        }
    }
    out
}

fn object_to_pairs(v: Option<&JsonValue>) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    if let Some(JsonValue::Object(o)) = v {
        for (k, val) in o {
            let key = match k.iter().position(|&c| c == 0) {
                Some(p) => k[..p].to_vec(),
                None => k.clone(),
            };
            out.push((key, json_string(Some(val))));
        }
    }
    out
}

impl RegressionTest {
    fn from_json(filename: &str, node: &JsonValue) -> Self {
        let s = |v: Option<&JsonValue>| lossy(&json_string(v));
        let mut u = RegressionTest { filename: filename.to_string(), http_code: 200, ..Default::default() };
        let JsonValue::Object(o) = node else {
            return u;
        };
        for (key, val) in o {
            match key.as_slice() {
                b"enabled" => u.enabled = json_int(Some(val)),
                b"title" => u.name = s(Some(val)),
                b"resource" => u.resource = s(Some(val)),
                b"client" => {
                    u.client_ip = s(val.get("ip"));
                    u.client_port = json_int(val.get("port"));
                }
                b"server" => {
                    u.server_ip = s(val.get("ip"));
                    u.server_port = json_int(val.get("port"));
                    u.hostname = s(val.get("hostname"));
                }
                b"request" => {
                    if let JsonValue::Object(r) = val {
                        for (k2, v2) in r {
                            match k2.as_slice() {
                                b"uri" => u.uri = json_string(Some(v2)),
                                b"method" => u.method = json_string(Some(v2)),
                                b"http_version" => {
                                    if let JsonValue::Number(n) = v2 {
                                        u.http_version = n.clone();
                                    }
                                }
                                b"headers" => u.request_headers = object_to_pairs(Some(v2)),
                                b"body" => u.request_body = array_to_str(Some(v2)),
                                _ => {}
                            }
                        }
                    }
                }
                b"response" => {
                    if let JsonValue::Object(r) = val {
                        for (k2, v2) in r {
                            match k2.as_slice() {
                                b"headers" => u.response_headers = object_to_pairs(Some(v2)),
                                b"body" => u.response_body = array_to_str(Some(v2)),
                                b"protocol" => u.response_protocol = s(Some(v2)),
                                _ => {}
                            }
                        }
                    }
                }
                b"expected" => {
                    if let JsonValue::Object(r) = val {
                        for (k2, v2) in r {
                            match k2.as_slice() {
                                b"audit_log" => u.audit_log = s(Some(v2)),
                                b"debug_log" => u.debug_log = s(Some(v2)),
                                b"error_log" => u.error_log = s(Some(v2)),
                                b"http_code" => u.http_code = json_int(Some(v2)),
                                b"parser_error" => u.parser_error = s(Some(v2)),
                                _ => {}
                            }
                        }
                    }
                }
                b"rules" => {
                    let mut rules = String::new();
                    if let JsonValue::Array(a) = val {
                        for l in a {
                            rules.push_str(&lossy(&json_string(Some(l))));
                            rules.push('\n');
                        }
                    }
                    u.rules = rules;
                }
                _ => {}
            }
        }
        u
    }
}

fn contains(s: &str, pattern: &str) -> bool {
    Regex::new(pattern).search(s.as_bytes()) > 0
}

fn clear_audit_log(filename: &str) {
    if !filename.is_empty() && std::fs::write(filename, b"").is_err() {
        println!("\nFailed to clear previous contents of audit log: {}", filename);
    }
}

fn get_audit_log_content(filename: &str) -> String {
    if filename.is_empty() {
        return String::new();
    }
    std::fs::read(filename).map(|b| lossy(&b)).unwrap_or_default()
}

struct Status {
    status: i64,
    location: String,
}

fn actions(r: &mut Status, t: &mut Transaction<'_>, server_log: &Mutex<String>) {
    let mut it = ModSecurityIntervention { status: 200, ..Default::default() };
    if t.intervention(&mut it) {
        if it.status != 0 {
            r.status = it.status as i64;
        }
        if let Some(u) = it.url_str() {
            r.location.push_str(&u);
        }
        if let Some(l) = it.log_str() {
            server_log.lock().unwrap().push_str(&l);
        }
        intervention::free(&mut it);
    }
}

struct Outcome {
    passed: bool,
    skipped: bool,
    disabled: bool,
    reason: String,
}

fn run_one(t: &RegressionTest, resources: &[&str]) -> Outcome {
    let mut out = Outcome { passed: false, skipped: false, disabled: false, reason: String::new() };
    if t.enabled == 0 {
        out.disabled = true;
        out.reason = "JSON disabled".to_string();
        return out;
    }

    // some tests (e.g. issue-1831.json) don't like it when data persists
    // between runs
    if cfg!(feature = "lmdb") {
        let _ = std::fs::remove_file("./modsec-shared-collections");
        let _ = std::fs::remove_file("./modsec-shared-collections-lock");
    }

    if !t.resource.is_empty() && !resources.contains(&t.resource.as_str()) {
        out.skipped = true;
        out.reason = format!("ModSecurity was not compiled with support to: {}", t.resource);
        return out;
    }

    // ModSecurityTestContext
    let server_log = Arc::new(Mutex::new(String::new()));
    let mut ms = ModSecurity::new();
    ms.set_connector_information("ModSecurity-regression v0.0.1-alpha (ModSecurity regression test utility)");
    {
        let sl = server_log.clone();
        ms.set_server_log_cb(Box::new(move |_data, entry| {
            if let ServerLogEntry::Text(s) = entry {
                let mut l = sl.lock().unwrap();
                l.push_str(s);
                l.push('\n');
            }
        }));
    }
    let mut rules = RulesSet::with_debug_log(Box::new(CustomDebugLog::new()));

    rules.load("SecDebugLogLevel 9");
    let filename =
        std::path::Path::new(&t.filename).file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default();
    if rules.load_with_ref(&t.rules, &filename) < 0 {
        // Parser error
        if t.parser_error.is_empty() {
            out.reason = format!("{}parse failed.{}\n{}\n", KRED, RESET, rules.get_parser_error());
            return out;
        }
        let s = rules.get_parser_error();
        if contains(&s, &t.parser_error) {
            out.passed = true;
        } else {
            out.reason = format!(
                "{}failed!{}\nExpected a parser error.\nExpected: {}\nProduced: {}\n",
                KRED, RESET, t.parser_error, s
            );
        }
        return out;
    } else if !t.parser_error.is_empty() {
        out.reason = format!("Expected a parser error.\nExpected: {}\n", t.parser_error);
        return out;
    }

    let mut r = Status { status: 200, location: String::new() };
    let audit_path = rules.properties.audit_log.path1.clone();
    {
        let mut tr = Transaction::new(&ms, &rules, None);
        if !t.hostname.is_empty() {
            tr.set_request_host_name(&t.hostname);
        }
        clear_audit_log(&audit_path);

        tr.process_connection(&t.client_ip, t.client_port as i32, &t.server_ip, t.server_port as i32);
        actions(&mut r, &mut tr, &server_log);

        tr.process_uri(&t.uri, &t.method, &t.http_version);
        actions(&mut r, &mut tr, &server_log);

        for (name, value) in &t.request_headers {
            tr.add_request_header(name, value);
        }
        tr.process_request_headers();
        actions(&mut r, &mut tr, &server_log);

        tr.append_request_body(&t.request_body);
        tr.process_request_body();
        actions(&mut r, &mut tr, &server_log);

        for (name, value) in &t.response_headers {
            tr.add_response_header(name, value);
        }
        tr.process_response_headers(r.status as i32, &t.response_protocol);
        actions(&mut r, &mut tr, &server_log);

        tr.append_response_body(&t.response_body);
        tr.process_response_body();
        actions(&mut r, &mut tr, &server_log);

        tr.process_logging();
    }

    let d = rules.properties.debug_log.as_any().downcast_ref::<CustomDebugLog>().expect("custom debug log");
    let server_log_s = server_log.lock().unwrap().clone();
    if !d.contains(&t.debug_log) {
        out.reason =
            format!("Debug log was not matching the expected results.\n{}Expecting: {}{}", KWHT, RESET, t.debug_log);
    } else if r.status != t.http_code {
        out.reason = format!("HTTP code mismatch. expecting: {} got: {}\n", t.http_code, r.status);
    } else if !contains(&server_log_s, &t.error_log) {
        out.reason =
            format!("Error log was not matching the expected results.\n{}Expecting: {}{}", KWHT, RESET, t.error_log);
    } else if !t.audit_log.is_empty() && !contains(&get_audit_log_content(&audit_path), &t.audit_log) {
        out.reason =
            format!("Audit log was not matching the expected results.\n{}Expecting: {}{}", KWHT, RESET, t.audit_log);
    } else {
        out.passed = true;
    }
    if !out.passed {
        out.reason.push_str(&format!(
            "\n{}Debug log:{}\n{}\n{}Error log:{}\n{}\n{}Audit log:{}\n{}\n",
            KWHT,
            RESET,
            d.log_messages(),
            KWHT,
            RESET,
            server_log_s,
            KWHT,
            RESET,
            get_audit_log_content(&audit_path)
        ));
    }
    out
}

fn main() {
    let envvar = format!("ModSecurity {} regression tests", MODSECURITY_VERSION);
    // SAFETY: single threaded at this point (no other threads spawned yet).
    unsafe { std::env::set_var("MODSECURITY", envvar) };

    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut automake = std::env::var_os("AUTOMAKE_TESTS").is_some();
    if args.first().map(|a| a == "automake").unwrap_or(false) {
        automake = true;
        args.remove(0);
    }
    let mut target = args.first().cloned().unwrap_or_else(|| DEFAULT_TEST_PATH.to_string());
    let mut test_number = 0usize;
    if let Some(pos) = target.find(':') {
        test_number = target[pos + 1..].parse().unwrap_or(0);
        target.truncate(pos);
    }

    let resources = resources();
    let mut files = load_tests(&target);
    files.sort_by(|a, b| a.0.cmp(&b.0));

    if !automake {
        println!("{:>4}{:<50}{:<70}{:<10}", "# ", "File Name", "Test Name", "Passed?");
        println!("{:>4}{:<50}{:<70}{:<10}", "--- ", "---------", "---------", "-------");
    }

    let (mut passed, mut failed, mut disabled, mut skipped) = (0, 0, 0, 0);
    let mut counter = 0;
    let mut failures = String::new();
    for (n, (path, tests)) in files.iter().enumerate() {
        if test_number != 0 && n + 1 != test_number {
            continue;
        }
        let filename =
            std::path::Path::new(path).file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default();
        for node in tests {
            counter += 1;
            let t = RegressionTest::from_json(path, node);
            let o = run_one(&t, &resources);
            let label = if o.disabled {
                disabled += 1;
                format!("{}disabled{}", KCYN, RESET)
            } else if o.skipped {
                skipped += 1;
                format!("{}skipped!{}", KCYN, RESET)
            } else if o.passed {
                passed += 1;
                format!("{}passed!{}", KGRN, RESET)
            } else {
                failed += 1;
                failures.push_str(&format!(
                    "{}Test failed.{}{} From: {}{}.\n{}Test name: {}{}.\n{}Reason: {}\n{}\n",
                    KRED, RESET, KWHT, RESET, t.filename, KWHT, RESET, t.name, KWHT, RESET, o.reason
                ));
                format!("{}failed!{}", KRED, RESET)
            };
            if automake {
                let res = if o.disabled || o.skipped {
                    "SKIP"
                } else if o.passed {
                    "PASS"
                } else {
                    "FAIL"
                };
                println!(":test-result: {} {}:{}", res, filename, t.name);
            } else {
                println!("{:>3} {:<50}{:<70}{}", counter, filename, t.name, label);
            }
        }
    }
    println!();
    if !automake {
        print!("{}", failures);
        print!("Ran a total of: {} regression tests - ", failed + passed);
        if failed == 0 {
            print!("{}All tests passed. {}", KGRN, RESET);
        } else {
            print!("{}{} failed. {}", KRED, failed, RESET);
        }
        println!("{}{} skipped test(s). {} disabled test(s).{}", KCYN, skipped, disabled, RESET);
    }
    std::process::exit(failed.min(255));
}
