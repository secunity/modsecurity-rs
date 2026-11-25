//! The response as the connector reports it: the status, the headers and
//! the body, each step followed by the rules of its phase.

use super::{BodyDirection, Transaction};
use crate::phases::Phases;
use crate::rules_set::properties::RuleEngine;
use crate::utils::string::split;

impl Transaction<'_> {
    /// Phase 3: records the response status and protocol and runs the
    /// response headers rules.
    pub fn process_response_headers(&mut self, code: u16, proto: &str) {
        crate::ms_dbg!(self, 4, "Starting phase RESPONSE_HEADERS. (SecRules 3)");
        self.http.http_code_returned = code;
        let off = self.vars.offset;
        self.vars.response_status.set(code.to_string().as_bytes(), off);
        self.vars.response_protocol.set(proto.as_bytes(), off);

        if self.rule_engine_state() == Some(RuleEngine::Disabled) {
            crate::ms_dbg!(self, 4, "Rule engine disabled, returning...");
            return;
        }
        self.evaluate_phase(Phases::ResponseHeaders);
    }

    /// Adds a response header (`RESPONSE_HEADERS`,
    /// `RESPONSE_CONTENT_TYPE`).
    pub fn add_response_header(&mut self, key: &[u8], value: &[u8]) {
        let off = self.vars.offset;
        self.vars.response_headers_names.set(key, key, off);
        self.vars.response_headers.set(key, value, off);
        if key.eq_ignore_ascii_case(b"content-type") {
            // Removes the charset=...
            let val = split(value, b';');
            if let Some(v) = val.first() {
                self.vars.response_content_type.set(v, 0);
            }
        }
    }

    fn response_type_is_inspected(&self) -> bool {
        let bi = &self.rules.properties.response_body_type_to_be_inspected.value;
        let ct = String::from_utf8_lossy(&self.vars.response_content_type.value().to_ascii_lowercase()).into_owned();
        bi.contains(&ct)
    }

    /// Phase 4: runs the response body rules, when the response body is
    /// inspected.
    pub fn process_response_body(&mut self) {
        crate::ms_dbg!(self, 4, "Starting phase RESPONSE_BODY. (SecRules 4)");

        if self.rule_engine_state() == Some(RuleEngine::Disabled) {
            crate::ms_dbg!(self, 4, "Rule engine disabled, returning...");
            return;
        }

        let props = &self.rules.properties;
        if props.settings.sec_response_body_access != Some(true) {
            let setting = match props.settings.sec_response_body_access {
                Some(_) => "SecResponseBodyAccess Off",
                None => "no SecResponseBodyAccess",
            };
            crate::ms_dbg!(self, 4, "Response body is disabled ({}), returning...", setting);
            return;
        }

        if !self.response_type_is_inspected() && props.response_body_type_to_be_inspected.set {
            crate::ms_dbg!(
                self,
                5,
                "Response Content-Type is {}. It is not marked to be inspected.",
                String::from_utf8_lossy(self.vars.response_content_type.value())
            );
            let mut valid = String::new();
            for i in props.response_body_type_to_be_inspected.value.iter() {
                valid.push_str(i);
                valid.push(' ');
            }
            crate::ms_dbg!(self, 8, "Content-Type(s) marked to be inspected: {}", valid);
            return;
        }
        if self.vars.outbound_data_error.value().is_empty() {
            let off = self.vars.offset;
            self.vars.outbound_data_error.set(b"0", off);
        }

        let off = self.vars.offset;
        self.vars.response_body.set(&self.http.response_body, off);
        self.vars.response_content_length.set(self.http.response_body.len().to_string().as_bytes(), off);
        self.evaluate_phase(Phases::ResponseBody);
    }

    /// Adds `buf` to the response body, within `SecResponseBodyLimit`,
    /// when its content type is inspected. Returns `false` when the body
    /// limit was hit and only a part was kept
    /// (`SecResponseBodyLimitAction ProcessPartial`); see
    /// `append_body` for the limit actions.
    pub fn append_response_body(&mut self, buf: &[u8]) -> bool {
        let props = &self.rules.properties;
        let bi = &props.response_body_type_to_be_inspected.value;
        if !self.response_type_is_inspected() && !bi.is_empty() {
            crate::ms_dbg!(
                self,
                4,
                "Not appending response body. Response Content-Type is {}. It is not marked to be inspected.",
                String::from_utf8_lossy(self.vars.response_content_type.value())
            );
            return true;
        }

        crate::ms_dbg!(
            self,
            9,
            "Appending response body: {} bytes. Limit set to: {}",
            buf.len() + self.http.response_body.len(),
            props.settings.response_body_limit.unwrap_or(0)
        );
        self.append_body(BodyDirection::Response, buf)
    }

    /// Whether the response body went past `SecResponseBodyLimit`: no
    /// more of it is kept for the rules.
    pub(crate) fn response_body_limit_reached(&self) -> bool {
        self.vars.outbound_data_error.value() == b"1"
    }

    /// The response body kept so far.
    pub fn response_body(&self) -> &[u8] {
        &self.http.response_body
    }

    /// The length of the response body kept so far.
    pub fn response_body_length(&self) -> usize {
        self.http.response_body.len()
    }

    /// Sets the response status (`RESPONSE_STATUS`).
    pub fn update_status_code(&mut self, code: u16) {
        self.http.http_code_returned = code;
        let off = self.vars.offset;
        self.vars.response_status.set(code.to_string().as_bytes(), off);
    }
}
