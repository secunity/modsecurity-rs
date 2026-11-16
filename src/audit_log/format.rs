//! Rendering of an audit log entry from a transaction: the native format
//! (sections `--<boundary>-A--` ... `Z`), its index line for concurrent
//! logs, and the JSON format.

use crate::audit_log::AuditLog as AL;
use crate::rule::message::LogParts;
use crate::rules_set::properties::rule_engine_state_string;
use crate::transaction::Transaction;
use crate::unique_id::UniqueId;
use crate::utils::json::JsonGen;
use crate::utils::string::{asc_time, dash_if_empty, double_to_string, to_hex_if_needed};

/// The index line of the native audit log format for an entry stored
/// in its own file (`SecAuditLogType Concurrent`).
pub(crate) fn native_index_line(t: &Transaction<'_>, filename: &str, size: f64, md5: &str) -> Vec<u8> {
    let tstr = crate::utils::system::strftime_local(t.time_stamp, "[%d/%b/%Y:%H:%M:%S %z]");
    let mut ss: Vec<u8> = Vec::new();
    let rh = &t.vars.request_headers;
    ss.extend_from_slice(&dash_if_empty(rh.resolve_first(b"Host").as_deref()));
    ss.push(b' ');
    ss.extend_from_slice(&dash_if_empty(Some(t.http.client_ip_address.as_bytes())));
    ss.push(b' ');
    let remote_user = crate::variables::computed::remote_user_name(t);
    ss.extend_from_slice(&dash_if_empty(Some(&remote_user)));
    ss.push(b' ');
    ss.extend_from_slice(tstr.as_bytes());
    ss.push(b' ');
    ss.push(b'"');
    ss.extend_from_slice(&dash_if_empty(Some(t.vars.request_method.evaluate())));
    ss.push(b' ');
    ss.extend_from_slice(cstr_prefix(&t.http.uri));
    ss.push(b' ');
    ss.extend_from_slice(b"HTTP/");
    ss.extend_from_slice(t.http.http_version.as_bytes());
    ss.extend_from_slice(b"\" ");
    ss.extend_from_slice(format!("{} {} ", t.http.http_code_returned, t.http.response_body.len()).as_bytes());
    ss.extend_from_slice(&dash_if_empty(rh.resolve_first(b"REFERER").as_deref()));
    ss.push(b' ');
    ss.push(b'"');
    ss.extend_from_slice(&dash_if_empty(rh.resolve_first(b"User-Agent").as_deref()));
    ss.extend_from_slice(b"\" ");
    ss.extend_from_slice(t.id.as_bytes());
    ss.push(b' ');
    ss.extend_from_slice(&dash_if_empty(rh.resolve_first(b"REFERER").as_deref()));
    ss.push(b' ');
    ss.extend_from_slice(filename.as_bytes());
    ss.push(b' ');
    ss.extend_from_slice(b"0 ");
    ss.extend_from_slice(double_to_string(size).as_bytes());
    ss.push(b' ');
    ss.extend_from_slice(b"md5:");
    ss.extend_from_slice(md5.as_bytes());
    ss.push(b'\n');
    ss
}

/// The audit log entry in the native format, with the given parts.
pub(crate) fn native(t: &Transaction<'_>, parts: i32, trailer: &str, prefix: &str) -> Vec<u8> {
    let tstr = crate::utils::system::strftime_local(t.time_stamp, "[%d/%b/%Y:%H:%M:%S %z]");
    let p = prefix.as_bytes();
    let mut a: Vec<u8> = Vec::new();
    let line = |a: &mut Vec<u8>, s: &[u8]| {
        a.extend_from_slice(s);
        a.push(b'\n');
    };
    let section = |a: &mut Vec<u8>, letter: &str| {
        a.extend_from_slice(p);
        a.extend_from_slice(format!("--{}-{}--\n", trailer, letter).as_bytes());
    };
    section(&mut a, "A");
    a.extend_from_slice(p);
    a.extend_from_slice(tstr.as_bytes());
    a.extend_from_slice(
        format!(
            " {} {} {} {} {}\n",
            t.id, t.http.client_ip_address, t.http.client_port, t.http.server_ip_address, t.http.server_port
        )
        .as_bytes(),
    );

    if parts & AL::B_AUDIT_LOG_PART != 0 {
        section(&mut a, "B");
        a.extend_from_slice(p);
        a.extend_from_slice(&dash_if_empty(Some(t.vars.request_method.evaluate())));
        a.push(b' ');
        a.extend_from_slice(cstr_prefix(&t.http.uri));
        a.extend_from_slice(b" HTTP/");
        line(&mut a, t.http.http_version.as_bytes());
        let mut l = Vec::new();
        t.vars.request_headers.resolve(&mut l);
        for h in &l {
            let pos = "REQUEST_HEADERS:".len();
            a.extend_from_slice(p);
            a.extend_from_slice(cstr_prefix(&h.key_with_collection()[pos.min(h.key_with_collection().len())..]));
            a.extend_from_slice(b": ");
            line(&mut a, cstr_prefix(h.value()));
        }
        line(&mut a, p);
    }
    if parts & AL::C_AUDIT_LOG_PART != 0 && !t.http.request_body.is_empty() {
        section(&mut a, "C");
        a.extend_from_slice(p);
        line(&mut a, &t.http.request_body);
        line(&mut a, p);
    }
    if parts & AL::D_AUDIT_LOG_PART != 0 {
        section(&mut a, "D");
        line(&mut a, p);
        // TODO (C++): write audit_log D part.
    }
    if parts & AL::E_AUDIT_LOG_PART != 0 && !t.http.response_body.is_empty() {
        let body = to_hex_if_needed(&t.http.response_body, false);
        section(&mut a, "E");
        if !body.is_empty() {
            a.extend_from_slice(p);
            line(&mut a, body.as_bytes());
        }
        line(&mut a, p);
    }
    if parts & AL::F_AUDIT_LOG_PART != 0 {
        section(&mut a, "F");
        a.extend_from_slice(p);
        line(&mut a, format!("HTTP/{} {}", t.http.http_version, t.http.http_code_returned).as_bytes());
        let mut l = Vec::new();
        t.vars.response_headers.resolve(&mut l);
        for h in &l {
            a.extend_from_slice(p);
            a.extend_from_slice(cstr_prefix(h.key()));
            a.extend_from_slice(b": ");
            line(&mut a, cstr_prefix(h.value()));
        }
    }
    line(&mut a, p);
    if parts & AL::G_AUDIT_LOG_PART != 0 {
        section(&mut a, "G");
        a.push(b'\n');
        // TODO (C++): write audit_log G part.
    }
    if parts & AL::H_AUDIT_LOG_PART != 0 {
        section(&mut a, "H");
        // A status of -1 reads as "no code" (the `%d` placeholder), as the
        // C++ comparison with -1 does.
        let code = Some(t.http.http_code_returned).filter(|&c| c != -1);
        for m in &t.outcome.rules_messages {
            a.extend_from_slice(p);
            line(&mut a, m.log(t, LogParts::empty(), code).as_bytes());
        }
        line(&mut a, p);
    }
    if parts & AL::I_AUDIT_LOG_PART != 0 {
        section(&mut a, "I");
        line(&mut a, p);
    }
    if parts & AL::J_AUDIT_LOG_PART != 0 {
        section(&mut a, "J");
        line(&mut a, p);
    }
    if parts & AL::K_AUDIT_LOG_PART != 0 {
        section(&mut a, "K");
        line(&mut a, p);
    }
    section(&mut a, "Z");
    a.push(b'\n');
    a
}

/// The audit log entry in the JSON format, with the given parts.
pub(crate) fn json(t: &Transaction<'_>, parts: i32) -> Vec<u8> {
    let ts = asc_time(t.time_stamp);
    let unique_id = UniqueId::unique_id();
    let mut g = JsonGen::new();

    g.map_open();
    g.string(b"transaction");
    g.map_open();

    // Part: A (header mandatory)
    g.add("client_ip", t.http.client_ip_address.as_bytes());
    g.add("time_stamp", ts.as_bytes());
    g.add("server_id", unique_id.as_bytes());
    g.add_num("client_port", t.http.client_port as i64);
    g.add("host_ip", t.http.server_ip_address.as_bytes());
    g.add_num("host_port", t.http.server_port as i64);
    g.add("unique_id", t.id.as_bytes());
    g.string(b"is_interrupted");
    g.bool(t.outcome.is_interrupted);

    // request
    g.string(b"request");
    g.map_open();
    g.add("method", &dash_if_empty(Some(t.vars.request_method.evaluate())));
    g.add("http_version", t.http.http_version.as_bytes());
    g.add("hostname", t.http.request_host_name.as_bytes());
    g.add("uri", &t.http.uri);
    if parts & AL::C_AUDIT_LOG_PART != 0 {
        // FIXME (C++): check for the binary content size.
        g.add("body", to_hex_if_needed(&t.http.request_body, false).as_bytes());
    }
    if parts & AL::B_AUDIT_LOG_PART != 0 {
        g.string(b"headers");
        g.map_open();
        let mut l = Vec::new();
        t.vars.request_headers.resolve(&mut l);
        for h in &l {
            g.string(to_hex_if_needed(cstr_prefix(h.key()), false).as_bytes());
            g.string(to_hex_if_needed(h.value(), false).as_bytes());
        }
        g.map_close();
    }
    g.map_close();

    // response
    g.string(b"response");
    g.map_open();
    if parts & AL::E_AUDIT_LOG_PART != 0 {
        g.add("body", &t.http.response_body);
    }
    g.add_num("http_code", t.http.http_code_returned as i64);
    if parts & AL::F_AUDIT_LOG_PART != 0 {
        g.string(b"headers");
        g.map_open();
        let mut l = Vec::new();
        t.vars.response_headers.resolve(&mut l);
        for h in &l {
            g.string(cstr_prefix(h.key()));
            g.string(h.value());
        }
        g.map_close();
    }
    g.map_close();

    // producer
    if parts & AL::H_AUDIT_LOG_PART != 0 {
        g.string(b"producer");
        g.map_open();
        g.add("modsecurity", t.ms.who_am_i().as_bytes());
        g.add("connector", t.ms.connector_information().as_bytes());
        g.add("secrules_engine", rule_engine_state_string(t.rule_engine_state()).as_bytes());
        g.string(b"components");
        g.array_open();
        for a in &t.rules.properties.components {
            g.string(a.as_bytes());
        }
        g.array_close();
        g.map_close();

        // messages
        g.string(b"messages");
        g.array_open();
        for a in &t.outcome.rules_messages {
            g.map_open();
            g.add("message", &a.message);
            g.string(b"details");
            g.map_open();
            g.add("match", &a.match_message());
            g.add("reference", &a.reference);
            g.add("ruleId", a.rule.rule_id.to_string().as_bytes());
            g.add("file", a.rule.file_name.as_bytes());
            g.add("lineNumber", a.rule.line_number.to_string().as_bytes());
            g.add("data", to_hex_if_needed(&a.data, false).as_bytes());
            g.add("severity", a.severity.to_string().as_bytes());
            g.add("ver", a.rule.ver.as_bytes());
            g.add("rev", a.rule.rev.as_bytes());
            g.string(b"tags");
            g.array_open();
            for b in &a.tags {
                g.string(b);
            }
            g.array_close();
            g.add("maturity", a.rule.maturity.to_string().as_bytes());
            g.add("accuracy", a.rule.accuracy.to_string().as_bytes());
            g.map_close();
            g.map_close();
        }
        g.array_close();
    }

    g.map_close();
    g.map_close();
    let mut log = g.into_buf();
    log.push(b'\n');
    log
}

/// The C++ code often writes `std::string::c_str()` into streams, which
/// stops at the first NUL byte.
fn cstr_prefix(s: &[u8]) -> &[u8] {
    match s.iter().position(|&c| c == 0) {
        Some(p) => &s[..p],
        None => s,
    }
}
