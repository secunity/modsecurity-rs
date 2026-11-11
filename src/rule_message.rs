//! Port of `headers/modsecurity/rule_message.h` and `src/rule_message.cc`.
//!
//! In C++ a `RuleMessage` holds references to its rule *and* to the
//! transaction, and copies of it are stored inside that same transaction
//! (`m_rulesMessages`). Rust cannot express that self reference, so the
//! message borrows only the rule (which outlives the transaction) and the
//! transaction is passed to the formatting functions instead.

use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;
use crate::utils::string::{limit_to, to_hex_if_needed};

/// `RuleMessage::LogMessageInfo`
pub const ERROR_LOG_TAIL_LOG_MESSAGE_INFO: i32 = 2;
pub const CLIENT_LOG_MESSAGE_INFO: i32 = 4;

#[derive(Debug, Clone)]
pub struct RuleMessage<'r> {
    pub rule: &'r RuleWithActions,
    pub data: Vec<u8>,
    pub is_disruptive: bool,
    pub match_: Vec<u8>,
    pub message: Vec<u8>,
    pub no_audit_log: bool,
    pub reference: Vec<u8>,
    pub save_message: bool,
    pub severity: i32,
    pub tags: Vec<Vec<u8>>,
}

impl<'r> RuleMessage<'r> {
    pub fn new(rule: &'r RuleWithActions) -> Self {
        let mut rm = RuleMessage {
            rule,
            data: Vec::new(),
            is_disruptive: false,
            match_: Vec::new(),
            message: Vec::new(),
            no_audit_log: false,
            reference: Vec::new(),
            save_message: true,
            severity: 0,
            tags: Vec::new(),
        };
        rm.reset(true);
        rm
    }

    pub fn reset(&mut self, reset_save_message: bool) {
        self.data.clear();
        self.is_disruptive = false;
        self.match_.clear();
        self.message.clear();
        self.no_audit_log = false;
        self.reference.clear();
        if reset_save_message {
            self.save_message = true;
        }
        self.severity = 0;
        self.tags.clear();
    }

    /// `log()` / `log(props)` / `log(props, responseCode)`; `code` -1 keeps
    /// a `%d` placeholder for the status code.
    pub fn log(&self, t: &Transaction<'_>, props: i32, code: i32) -> String {
        let mut msg: Vec<u8> = Vec::with_capacity(2048);
        if props & CLIENT_LOG_MESSAGE_INFO != 0 {
            msg.extend_from_slice(format!("[client {}] ", t.client_ip_address).as_bytes());
        }
        if self.is_disruptive {
            msg.extend_from_slice(b"ModSecurity: Access denied with code ");
            if code == -1 {
                msg.extend_from_slice(b"%d");
            } else {
                msg.extend_from_slice(code.to_string().as_bytes());
            }
            msg.extend_from_slice(format!(" (phase {}). ", self.get_phase()).as_bytes());
        } else {
            msg.extend_from_slice(b"ModSecurity: Warning. ");
        }
        msg.extend_from_slice(&self.match_);
        msg.extend_from_slice(&Self::details(self, t));
        if props & ERROR_LOG_TAIL_LOG_MESSAGE_INFO != 0 {
            msg.push(b' ');
            msg.extend_from_slice(&Self::error_log_tail(t));
        }
        to_hex_if_needed(&msg, false)
    }

    /// `errorLog()`
    pub fn error_log(&self, t: &Transaction<'_>) -> String {
        self.log(t, CLIENT_LOG_MESSAGE_INFO | ERROR_LOG_TAIL_LOG_MESSAGE_INFO, -1)
    }

    /// `_details`
    pub fn details(rm: &RuleMessage<'_>, t: &Transaction<'_>) -> Vec<u8> {
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
        push(t.request_host_name.as_bytes());
        push(b"\"]");
        push(b" [uri \"");
        push(&limit_to(200, &t.uri_no_query_string_decoded));
        push(b"\"]");
        push(format!(" [unique_id \"{}\"]", t.id).as_bytes());
        push(b" [ref \"");
        push(&limit_to(200, &rm.reference));
        push(b"\"]");
        msg
    }

    /// `_errorLogTail`
    pub fn error_log_tail(t: &Transaction<'_>) -> Vec<u8> {
        let mut msg: Vec<u8> = Vec::new();
        msg.extend_from_slice(format!("[hostname \"{}\"]", t.server_ip_address).as_bytes());
        msg.extend_from_slice(b" [uri \"");
        msg.extend_from_slice(&limit_to(200, &t.uri_no_query_string_decoded));
        msg.extend_from_slice(b"\"]");
        msg.extend_from_slice(format!(" [unique_id \"{}\"]", t.id).as_bytes());
        msg
    }

    /// `getPhase`: the SecLang phase number (1..5) of the rule.
    pub fn get_phase(&self) -> i32 {
        self.rule.get_phase() - 1
    }
}
