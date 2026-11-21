//! A rule message as an entry of `messages` in the JSON audit log.

use modsecurity_compat::json::JsonGen;

use super::RuleMessage;
use crate::utils::string::to_hex_if_needed;

impl RuleMessage<'_> {
    /// Writes the message as a JSON object: `message` and `details`.
    pub(crate) fn write_json(&self, g: &mut JsonGen) {
        g.map_open();
        g.add("message", &self.message);
        g.string(b"details");
        g.map_open();
        g.add("match", &self.match_message());
        g.add("reference", &self.reference);
        g.add("ruleId", self.rule.logged_id().to_string().as_bytes());
        g.add("file", self.rule.file_name.as_bytes());
        g.add("lineNumber", self.rule.line_number.to_string().as_bytes());
        g.add("data", to_hex_if_needed(&self.data, false).as_bytes());
        // 0 without a severity.
        g.add("severity", self.severity.unwrap_or(0).to_string().as_bytes());
        g.add("ver", self.rule.ver.as_bytes());
        g.add("rev", self.rule.rev.as_bytes());
        g.string(b"tags");
        g.array_open();
        for tag in &self.tags {
            g.string(tag);
        }
        g.array_close();
        g.add("maturity", self.rule.maturity.to_string().as_bytes());
        g.add("accuracy", self.rule.accuracy.to_string().as_bytes());
        g.map_close();
        g.map_close();
    }
}
