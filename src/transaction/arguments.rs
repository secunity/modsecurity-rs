//! Argument insertion shared by URI, form and structured-body parsing.
//!
//! This view borrows only argument state and logging/configuration context,
//! leaving the transaction's body and parser available for independent borrows.

use super::TransactionAnchoredVariables;
use crate::rules_set::RulesSet;
use crate::utils::decode::urldecode_nonstrict_inplace;
use crate::utils::string::{double_to_string, ssplit_pair};

pub(super) struct ArgumentWriter<'a> {
    pub vars: &'a mut TransactionAnchoredVariables,
    pub combined_size: &'a mut f64,
    pub rules: &'a RulesSet,
    pub id: &'a str,
    pub uri: &'a [u8],
}

impl ArgumentWriter<'_> {
    pub fn add(&mut self, origin: &str, key: &[u8], value: &[u8], mut offset: usize) -> bool {
        let log = &self.rules.properties.debug_log;
        if log.enabled(4) {
            log.write_ctx(
                4,
                self.id,
                &String::from_utf8_lossy(self.uri),
                &format!(
                    "Adding request argument ({}): name \"{}\", value \"{}\"",
                    origin,
                    String::from_utf8_lossy(key),
                    String::from_utf8_lossy(value)
                ),
            );
        }
        if let Some(limit) = self.rules.properties.arguments_limit
            && self.vars.args.len() >= limit as usize
        {
            if log.enabled(4) {
                log.write_ctx(
                    4,
                    self.id,
                    &String::from_utf8_lossy(self.uri),
                    &format!("Skipping request argument, over limit ({})", limit),
                );
            }
            return false;
        }
        offset = offset + key.len() + 1;
        self.vars.args.set(key, value, offset);
        match origin {
            "GET" => self.vars.args_get.set(key, value, offset),
            "POST" => self.vars.args_post.set(key, value, offset),
            _ => {}
        }
        *self.combined_size += (key.len() + value.len()) as f64;
        let size = double_to_string(*self.combined_size);
        self.vars.args_combined_size.set_with_len(size.as_bytes(), offset - key.len() - 1, key.len());
        self.vars.args_combined_size.set_with_len(size.as_bytes(), offset, value.len());
        true
    }

    pub fn extract(&mut self, origin: &str, body: &[u8], mut offset: usize) {
        let separator = self
            .rules
            .properties
            .sec_argument_separator
            .as_ref()
            .and_then(|s| s.as_bytes().first().copied())
            .unwrap_or(b'&');
        // Like std::getline, an empty input or trailing separator produces
        // no extra argument. Borrow each segment instead of copying the
        // whole input into a vector of parts before decoding it.
        for part in body.split_inclusive(|&byte| byte == separator) {
            let part = part.strip_suffix(&[separator]).unwrap_or(part);
            let (mut key, mut value) = ssplit_pair(part, b'=');
            let mut invalid_count = 0;
            urldecode_nonstrict_inplace(&mut key, &mut invalid_count);
            urldecode_nonstrict_inplace(&mut value, &mut invalid_count);
            if invalid_count > 0 {
                self.vars.url_encoded_error.set(b"1", self.vars.offset);
            }
            // Form decoding keeps scanning after an argument limit is hit,
            // so a later invalid escape still sets URLENCODED_ERROR.
            self.add(origin, &key, &value, offset);
            offset = offset + part.len() + 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::modsecurity::ModSecurity;
    use crate::request_body_processor::multipart::test_support::{log, new_rules};
    use crate::transaction::Transaction;
    use crate::variable_origin::VariableOrigin;

    #[test]
    fn form_decoding_preserves_bytes_offsets_and_limit_logging() {
        let ms = ModSecurity::new();
        let mut rules = new_rules();
        rules.properties.sec_argument_separator = Some(";".into());
        rules.properties.arguments_limit = Some(2);
        let mut t = Transaction::new(&ms, &rules, None);
        t.vars.offset = 77;
        assert!(t.extract_arguments("POST", b"a%00=%ff+;bare;bad=%Q0;", 10));
        assert_eq!(t.vars.args_post.resolve_first(b"a\0").unwrap(), b"\xff ");
        assert_eq!(t.vars.args_post.resolve_first(b"bare").unwrap(), b"");
        assert_eq!(t.vars.args_post.len(), 2);
        assert!(t.vars.args_get.is_empty());
        assert_eq!(t.vars.url_encoded_error.value, b"1");
        assert_eq!(t.vars.url_encoded_error.offset, 77);
        assert_eq!(t.vars.args_combined_size.value, b"8.000000");
        let mut values = Vec::new();
        t.vars.args_combined_size.evaluate_into(&mut values);
        assert_eq!(
            values[0].origin(),
            &[
                VariableOrigin::new(2, 10),
                VariableOrigin::new(2, 13),
                VariableOrigin::new(4, 20),
                VariableOrigin::new(0, 25),
            ]
        );
        assert!(log(&rules).ends_with(&[
            "Adding request argument (POST): name \"bad\", value \"%Q0\"".into(),
            "Skipping request argument, over limit (2)".into(),
        ]));
    }

    #[test]
    fn form_separators_preserve_empty_arguments_and_origin_case() {
        let ms = ModSecurity::new();
        for (body, count) in [(&b""[..], 0), (b"&", 1), (b"&&", 2), (b"a=1&", 1), (b"&a=1&&", 3)] {
            let rules = new_rules();
            let mut t = Transaction::new(&ms, &rules, None);
            t.extract_arguments("GET", body, 0);
            assert_eq!(t.vars.args.len(), count, "{body:?}");
            assert_eq!(t.vars.args_get.len(), count);
        }
        let rules = new_rules();
        let mut t = Transaction::new(&ms, &rules, None);
        t.extract_arguments("get", b"a=1", 0);
        assert_eq!(t.vars.args.resolve_first(b"a").unwrap(), b"1");
        assert!(t.vars.args_get.is_empty());
    }
}
