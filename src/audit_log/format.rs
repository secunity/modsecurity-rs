//! Rendering of an audit log entry from a transaction: the native format
//! (sections `--<boundary>-A--` ... `Z`), its index line for concurrent
//! logs, and the JSON format.

use crate::audit_log::Parts;
use crate::rule::message::LogParts;
use crate::rules_set::properties::rule_engine_state_string;
use crate::transaction::Transaction;
use crate::unique_id::UniqueId;
use crate::utils::string::{dash_if_empty, to_hex_if_needed};
use crate::utils::system::strftime_local;
use modsecurity_compat::json::JsonGen;

/// The index line of the native audit log format for an entry stored
/// in its own file (`SecAuditLogType Concurrent`).
pub(crate) fn native_index_line(t: &Transaction<'_>, filename: &str, size: usize, md5: &str) -> Vec<u8> {
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
    ss.extend_from_slice(&dash_if_empty(Some(t.vars.request_method.value())));
    ss.push(b' ');
    ss.extend_from_slice(&t.http.uri);
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
    ss.extend_from_slice(size.to_string().as_bytes());
    ss.push(b' ');
    ss.extend_from_slice(b"md5:");
    ss.extend_from_slice(md5.as_bytes());
    ss.push(b'\n');
    ss
}

/// The audit log entry in the native format, with the given parts.
pub(crate) fn native(t: &Transaction<'_>, parts: Parts, trailer: &str, prefix: &str) -> Vec<u8> {
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

    if parts.contains(Parts::B) {
        section(&mut a, "B");
        a.extend_from_slice(p);
        a.extend_from_slice(&dash_if_empty(Some(t.vars.request_method.value())));
        a.push(b' ');
        a.extend_from_slice(&t.http.uri);
        a.extend_from_slice(b" HTTP/");
        line(&mut a, t.http.http_version.as_bytes());
        let mut l = Vec::new();
        t.vars.request_headers.resolve(&mut l);
        for h in &l {
            let pos = "REQUEST_HEADERS:".len();
            a.extend_from_slice(p);
            a.extend_from_slice(&h.key_with_collection()[pos.min(h.key_with_collection().len())..]);
            a.extend_from_slice(b": ");
            line(&mut a, h.value());
        }
        line(&mut a, p);
    }
    if parts.contains(Parts::C) && !t.http.request_body.is_empty() {
        section(&mut a, "C");
        a.extend_from_slice(p);
        line(&mut a, &t.http.request_body);
        line(&mut a, p);
    }
    if parts.contains(Parts::D) {
        section(&mut a, "D");
        line(&mut a, p);
        // Not implemented: part D has a header and no content.
    }
    if parts.contains(Parts::E) && !t.http.response_body.is_empty() {
        let body = to_hex_if_needed(&t.http.response_body, false);
        section(&mut a, "E");
        if !body.is_empty() {
            a.extend_from_slice(p);
            line(&mut a, body.as_bytes());
        }
        line(&mut a, p);
    }
    if parts.contains(Parts::F) {
        section(&mut a, "F");
        a.extend_from_slice(p);
        line(&mut a, format!("HTTP/{} {}", t.http.http_version, t.http.http_code_returned).as_bytes());
        let mut l = Vec::new();
        t.vars.response_headers.resolve(&mut l);
        for h in &l {
            a.extend_from_slice(p);
            a.extend_from_slice(h.key());
            a.extend_from_slice(b": ");
            line(&mut a, h.value());
        }
    }
    line(&mut a, p);
    if parts.contains(Parts::G) {
        section(&mut a, "G");
        a.push(b'\n');
        // Not implemented: part G has a header and no content.
    }
    if parts.contains(Parts::H) {
        section(&mut a, "H");
        let code = Some(t.http.http_code_returned);
        for m in &t.outcome.rules_messages {
            a.extend_from_slice(p);
            line(&mut a, m.log(t, LogParts::empty(), code).as_bytes());
        }
        line(&mut a, p);
    }
    if parts.contains(Parts::I) {
        section(&mut a, "I");
        line(&mut a, p);
    }
    if parts.contains(Parts::J) {
        section(&mut a, "J");
        line(&mut a, p);
    }
    if parts.contains(Parts::K) {
        section(&mut a, "K");
        line(&mut a, p);
    }
    section(&mut a, "Z");
    a.push(b'\n');
    a
}

/// The audit log entry in the JSON format, with the given parts.
pub(crate) fn json(t: &Transaction<'_>, parts: Parts) -> Vec<u8> {
    let ts = strftime_local(t.time_stamp, "%c");
    let unique_id = UniqueId::unique_id();
    let mut g = JsonGen::new();

    g.map_open();
    g.string(b"transaction");
    g.map_open();

    // Part: A (header mandatory)
    g.add("client_ip", t.http.client_ip_address.as_bytes());
    g.add("time_stamp", ts.as_bytes());
    g.add("server_id", unique_id.as_bytes());
    g.add_num("client_port", t.http.client_port.into());
    g.add("host_ip", t.http.server_ip_address.as_bytes());
    g.add_num("host_port", t.http.server_port.into());
    g.add("unique_id", t.id.as_bytes());
    g.string(b"is_interrupted");
    g.bool(t.outcome.is_interrupted);

    // request
    g.string(b"request");
    g.map_open();
    g.add("method", &dash_if_empty(Some(t.vars.request_method.value())));
    g.add("http_version", t.http.http_version.as_bytes());
    g.add("hostname", t.http.request_host_name.as_bytes());
    g.add("uri", &t.http.uri);
    if parts.contains(Parts::C) {
        g.add("body", to_hex_if_needed(&t.http.request_body, false).as_bytes());
    }
    if parts.contains(Parts::B) {
        g.string(b"headers");
        g.map_open();
        let mut l = Vec::new();
        t.vars.request_headers.resolve(&mut l);
        for h in &l {
            g.string(to_hex_if_needed(h.key(), false).as_bytes());
            g.string(to_hex_if_needed(h.value(), false).as_bytes());
        }
        g.map_close();
    }
    g.map_close();

    // response
    g.string(b"response");
    g.map_open();
    if parts.contains(Parts::E) {
        g.add("body", &t.http.response_body);
    }
    g.add_num("http_code", t.http.http_code_returned.into());
    if parts.contains(Parts::F) {
        g.string(b"headers");
        g.map_open();
        let mut l = Vec::new();
        t.vars.response_headers.resolve(&mut l);
        for h in &l {
            g.string(h.key());
            g.string(h.value());
        }
        g.map_close();
    }
    g.map_close();

    // producer
    if parts.contains(Parts::H) {
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
        for message in &t.outcome.rules_messages {
            message.write_json(&mut g);
        }
        g.array_close();
    }

    g.map_close();
    g.map_close();
    let mut log = g.into_buf();
    log.push(b'\n');
    log
}
