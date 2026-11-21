//! A rule message as text: the error log line, and the lines of the `H`
//! part of the native audit log.

use super::{LogParts, RuleMessage};
use crate::transaction::Transaction;
use crate::utils::string::{limit_to, to_hex_if_needed};

impl RuleMessage<'_> {
    /// The log line of the message, with the optional `parts`. `code` is
    /// the status code of a disruptive message (`Access denied with code
    /// 403`); without one the line says `Access denied`.
    pub fn log(&self, t: &Transaction<'_>, parts: LogParts, code: Option<u16>) -> String {
        let (mut line, after_code) = self.log_around_code(t, parts);
        if let (true, Some(code)) = (self.is_disruptive, code) {
            line.push_str(" with code ");
            line.push_str(&code.to_string());
        }
        line.push_str(&after_code);
        line
    }

    /// The log line of the message in two parts: the status code of a
    /// disruptive message goes between them (`... Access denied` and
    /// ` (phase 1). ...`). For a message that does not disrupt the line is
    /// their concatenation.
    pub(crate) fn log_around_code(&self, t: &Transaction<'_>, parts: LogParts) -> (String, String) {
        let mut before: Vec<u8> = Vec::with_capacity(64);
        if parts.contains(LogParts::CLIENT) {
            before.extend_from_slice(format!("[client {}] ", t.http.client_ip_address).as_bytes());
        }
        let mut after: Vec<u8> = Vec::with_capacity(2048);
        if self.is_disruptive {
            before.extend_from_slice(b"ModSecurity: Access denied");
            after.extend_from_slice(format!(" (phase {}). ", self.phase_number()).as_bytes());
        } else {
            before.extend_from_slice(b"ModSecurity: Warning. ");
        }
        after.extend_from_slice(&self.match_message());
        after.extend_from_slice(&Self::details(self, t));
        if parts.contains(LogParts::ERROR_LOG_TAIL) {
            after.push(b' ');
            after.extend_from_slice(&Self::error_log_tail(t));
        }
        // Escaping works byte by byte: escaping the parts apart is
        // escaping the line.
        (to_hex_if_needed(&before, false), to_hex_if_needed(&after, false))
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
        push(format!(" [id \"{}\"]", r.logged_id()).as_bytes());
        push(format!(" [rev \"{}\"]", to_hex_if_needed(r.rev.as_bytes(), true)).as_bytes());
        push(b" [msg \"");
        push(&rm.message);
        push(b"\"]");
        push(format!(" [data \"{}\"]", to_hex_if_needed(&limit_to(200, &rm.data), true)).as_bytes());
        // 0 without a severity.
        push(format!(" [severity \"{}\"]", rm.severity.unwrap_or(0)).as_bytes());
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
