//! Argument insertion shared by URI, form and structured-body parsing.
//!
//! This view borrows only argument state and logging/configuration context,
//! leaving the transaction's body and parser available for independent borrows.

use super::TransactionAnchoredVariables;
use crate::rules_set::RulesSet;
use crate::utils::string::ssplit_pair;
use crate::variables::variable_origin::VariableOrigin;
use modsecurity_transformations::url::urldecode_nonstrict_inplace;

/// Where an argument comes from. Every argument is in `ARGS`; those of
/// the query string are also in `ARGS_GET`, those of a URL-encoded form
/// body in `ARGS_POST`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArgumentOrigin {
    /// The query string.
    Get,
    /// A URL-encoded form body.
    Post,
    /// A JSON body.
    Json,
    /// An XML body (`SecParseXmlIntoArgs`).
    #[cfg_attr(not(feature = "libxml2"), allow(dead_code))]
    Xml,
}

impl ArgumentOrigin {
    /// The name the debug log gives it.
    fn name(self) -> &'static str {
        match self {
            ArgumentOrigin::Get => "GET",
            ArgumentOrigin::Post => "POST",
            ArgumentOrigin::Json => "JSON",
            ArgumentOrigin::Xml => "XML",
        }
    }
}

pub(super) struct ArgumentWriter<'a> {
    pub vars: &'a mut TransactionAnchoredVariables,
    pub combined_size: &'a mut usize,
    pub rules: &'a RulesSet,
    pub id: &'a str,
    pub uri: &'a [u8],
}

impl ArgumentWriter<'_> {
    pub fn add(&mut self, origin: ArgumentOrigin, key: &[u8], value: &[u8], mut offset: usize) -> bool {
        let log = &self.rules.properties.debug_log;
        if log.enabled(4) {
            log.write_ctx(
                4,
                self.id,
                &String::from_utf8_lossy(self.uri),
                &format!(
                    "Adding request argument ({}): name \"{}\", value \"{}\"",
                    origin.name(),
                    String::from_utf8_lossy(key),
                    String::from_utf8_lossy(value)
                ),
            );
        }
        if let Some(limit) = self.rules.properties.settings.arguments_limit
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
            ArgumentOrigin::Get => self.vars.args_get.set(key, value, offset),
            ArgumentOrigin::Post => self.vars.args_post.set(key, value, offset),
            ArgumentOrigin::Json | ArgumentOrigin::Xml => {}
        }
        *self.combined_size += key.len() + value.len();
        let size = self.combined_size.to_string();
        // The size comes from every argument: each adds its name and value
        // to the origins.
        let origins =
            [VariableOrigin::new(key.len(), offset - key.len() - 1), VariableOrigin::new(value.len(), offset)];
        self.vars.args_combined_size.set_adding_origins(size.as_bytes(), origins);
        true
    }

    pub fn extract(&mut self, origin: ArgumentOrigin, body: &[u8], mut offset: usize) {
        let separator = self
            .rules
            .properties
            .settings
            .sec_argument_separator
            .as_ref()
            .and_then(|s| s.as_bytes().first().copied())
            .unwrap_or(b'&');
        // An empty input or a trailing separator produces
        // no extra argument. Borrow each segment instead of copying the
        // whole input into a vector of parts before decoding it.
        for part in body.split_inclusive(|&byte| byte == separator) {
            let part = part.strip_suffix(&[separator]).unwrap_or(part);
            let (mut key, mut value) = ssplit_pair(part, b'=');
            // A bad escape in the name counts as well as one in the value.
            let invalid_count = urldecode_nonstrict_inplace(&mut key) + urldecode_nonstrict_inplace(&mut value);
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
    use super::ArgumentOrigin;
    use crate::instance::ModSecurity;
    use crate::transaction::Transaction;
    use crate::transaction::body::tests::multipart::test_support::{log, new_rules};
    use crate::variables::variable_origin::VariableOrigin;

    #[test]
    fn form_decoding_preserves_bytes_offsets_and_limit_logging() {
        let ms = ModSecurity::new();
        let mut rules = new_rules();
        rules.properties.settings.sec_argument_separator = Some(";".into());
        rules.properties.settings.arguments_limit = Some(2);
        let mut t = Transaction::new(&ms, &rules, None);
        t.vars.offset = 77;
        t.extract_arguments(ArgumentOrigin::Post, b"a%00=%ff+;bare;bad=%Q0;", 10);
        assert_eq!(t.vars.args_post.resolve_first(b"a\0").unwrap(), b"\xff ");
        assert_eq!(t.vars.args_post.resolve_first(b"bare").unwrap(), b"");
        assert_eq!(t.vars.args_post.len(), 2);
        assert!(t.vars.args_get.is_empty());
        assert_eq!(t.vars.url_encoded_error.value(), b"1");
        assert_eq!(t.vars.url_encoded_error.offset(), 77);
        assert_eq!(t.vars.args_combined_size.value(), b"8");
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

    /// An invalid escape in the name of an argument sets URLENCODED_ERROR,
    /// as one in its value does.
    #[test]
    fn invalid_escape_in_an_argument_name() {
        let ms = ModSecurity::new();
        for (body, error) in [(&b"a%zz=b"[..], true), (b"a=b%zz", true), (b"a%41=b%20", false), (b"a%=b", true)] {
            let rules = new_rules();
            let mut t = Transaction::new(&ms, &rules, None);
            t.extract_arguments(ArgumentOrigin::Get, body, 0);
            assert_eq!(t.vars.url_encoded_error.value() == b"1", error, "{body:?}");
        }
    }

    #[test]
    fn form_separators_preserve_empty_arguments_and_origins() {
        let ms = ModSecurity::new();
        for (body, count) in [(&b""[..], 0), (b"&", 1), (b"&&", 2), (b"a=1&", 1), (b"&a=1&&", 3)] {
            let rules = new_rules();
            let mut t = Transaction::new(&ms, &rules, None);
            t.extract_arguments(ArgumentOrigin::Get, body, 0);
            assert_eq!(t.vars.args.len(), count, "{body:?}");
            assert_eq!(t.vars.args_get.len(), count);
        }
        // JSON arguments are only in ARGS.
        let rules = new_rules();
        let mut t = Transaction::new(&ms, &rules, None);
        t.argument_writer().add(ArgumentOrigin::Json, b"a", b"1", 0);
        assert_eq!(t.vars.args.resolve_first(b"a").unwrap(), b"1");
        assert!(t.vars.args_get.is_empty() && t.vars.args_post.is_empty());
    }
}
