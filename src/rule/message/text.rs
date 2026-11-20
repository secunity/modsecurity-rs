//! A rule message as text: the error log line, and the lines of the `H`
//! part of the native audit log.

use super::{LogParts, RuleMessage};
use crate::transaction::Transaction;
use crate::utils::string::{limit_to, to_hex_if_needed};

impl RuleMessage<'_> {
    /// The log line of the message, with the optional `parts`. `code` is
    /// the status code of a disruptive message; without one the line keeps
    /// a `%d` placeholder for it.
    pub fn log(&self, t: &Transaction<'_>, parts: LogParts, code: Option<u16>) -> String {
        let mut msg: Vec<u8> = Vec::with_capacity(2048);
        if parts.contains(LogParts::CLIENT) {
            msg.extend_from_slice(format!("[client {}] ", t.http.client_ip_address).as_bytes());
        }
        if self.is_disruptive {
            msg.extend_from_slice(b"ModSecurity: Access denied with code ");
            match code {
                Some(code) => msg.extend_from_slice(code.to_string().as_bytes()),
                None => msg.extend_from_slice(b"%d"),
            }
            msg.extend_from_slice(format!(" (phase {}). ", self.phase_number()).as_bytes());
        } else {
            msg.extend_from_slice(b"ModSecurity: Warning. ");
        }
        msg.extend_from_slice(&self.match_message());
        msg.extend_from_slice(&Self::details(self, t));
        if parts.contains(LogParts::ERROR_LOG_TAIL) {
            msg.push(b' ');
            msg.extend_from_slice(&Self::error_log_tail(t));
        }
        to_hex_if_needed(&msg, false)
    }

    /// The error log line: [`Self::log`] with the client address and the
    /// error log tail.
    pub fn error_log(&self, t: &Transaction<'_>) -> String {
        self.log(t, LogParts::CLIENT | LogParts::ERROR_LOG_TAIL, None)
    }

    /// The details of the log line: ` [file "..."] [line "..."] ...`.
    pub(crate) fn details(rm: &RuleMessage<'_>, t: &Transaction<'_>) -> Vec<u8> {
        let r = rm.rule;
        let mut msg: Vec<u8> = Vec::new();
        let mut push = |s: &[u8]| msg.extend_from_slice(s);
        push(format!(" [file \"{}\"]", r.file_name).as_bytes());
        push(format!(" [line \"{}\"]", r.line_number).as_bytes());
        push(format!(" [id \"{}\"]", r.rule_id).as_bytes());
        push(format!(" [rev \"{}\"]", to_hex_if_needed(r.rev.as_bytes(), true)).as_bytes());
        push(b" [msg \"");
        push(&rm.message);
        push(b"\"]");
        push(format!(" [data \"{}\"]", to_hex_if_needed(&limit_to(200, &rm.data), true)).as_bytes());
        push(format!(" [severity \"{}\"]", rm.severity).as_bytes());
        push(format!(" [ver \"{}\"]", to_hex_if_needed(r.ver.as_bytes(), true)).as_bytes());
        push(format!(" [maturity \"{}\"]", r.maturity).as_bytes());
        push(format!(" [accuracy \"{}\"]", r.accuracy).as_bytes());
        for a in &rm.tags {
            push(format!(" [tag \"{}\"]", to_hex_if_needed(a, true)).as_bytes());
        }
        push(b" [hostname \"");
        push(t.http.request_host_name.as_bytes());
        push(b"\"]");
        push(b" [uri \"");
        push(&limit_to(200, &t.http.uri_no_query_string_decoded));
        push(b"\"]");
        push(format!(" [unique_id \"{}\"]", t.id).as_bytes());
        push(b" [ref \"");
        push(&limit_to(200, &rm.reference));
        push(b"\"]");
        msg
    }

    /// The tail of an error log line: the server address (as `hostname`),
    /// the uri and the unique id.
    pub(crate) fn error_log_tail(t: &Transaction<'_>) -> Vec<u8> {
        let mut msg: Vec<u8> = Vec::new();
        msg.extend_from_slice(format!("[hostname \"{}\"]", t.http.server_ip_address).as_bytes());
        msg.extend_from_slice(b" [uri \"");
        msg.extend_from_slice(&limit_to(200, &t.http.uri_no_query_string_decoded));
        msg.extend_from_slice(b"\"]");
        msg.extend_from_slice(format!(" [unique_id \"{}\"]", t.id).as_bytes());
        msg
    }
}
