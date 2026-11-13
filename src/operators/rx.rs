//! Port of `src/operators/rx.cc`, `src/operators/rx.h`.

use crate::operators::operator::{Operator, Param, log_offset, report_regex_compile_error, report_regex_search_error};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;
use crate::utils::regex::{Regex, RegexResult, SMatchCapture};

/// C++ `kRxMultiLine`: `$` only matches at the very end of the subject when
/// built with `MODSEC_REGEX_DOLLAR_ENDONLY` (cargo feature
/// `regex-dollar-endonly`), otherwise the pattern is multi-line.
const MULTI_LINE: bool = !cfg!(feature = "regex-dollar-endonly");

#[derive(Debug)]
pub struct Rx {
    param: Param,
    re: Option<Regex>,
}

impl Rx {
    pub fn new(param: RunTimeString) -> Self {
        Rx { param: Param::expanded_in_message(param), re: None }
    }

    fn contains_macro(&self) -> bool {
        self.param.contains_macro()
    }
}

impl Rx {
    /// Whether `input` matches; `None` when the regular expression failed
    /// (it does not compile, or it hit the match limits), which is neither
    /// a match nor a mismatch.
    fn try_match(
        &self,
        t: &mut Transaction<'_>,
        rule: &RuleWithActions,
        input: &[u8],
        rm: &mut RuleMessage<'_>,
    ) -> Option<bool> {
        if self.param.literal.is_empty() && !self.contains_macro() {
            return Some(true);
        }

        let re_owned;
        let re: &Regex = if self.contains_macro() {
            let eparam = self.param.value(t);
            re_owned = Regex::with_options(&eparam, false, MULTI_LINE);
            &re_owned
        } else if let Some(re) = self.re.as_ref() {
            re
        } else {
            // init() was not called: compile the parameter now.
            re_owned = Regex::with_options(&self.param.literal, false, MULTI_LINE);
            &re_owned
        };

        if re.has_error() {
            report_regex_compile_error(t, re);
            return None;
        }

        // (`utils::regex` guards against dangling empty-slice pointers.)
        let subject: &[u8] = input;
        let mut captures: Vec<SMatchCapture> = Vec::new();
        let match_limit = t.rules.properties.pcre_match_limit.map_or(0, u64::from);
        let regex_result = re.search_one_match(subject, &mut captures, match_limit);

        if regex_result != RegexResult::Ok {
            report_regex_search_error(t, re, regex_result, "rx");
            return None;
        }

        if rule.has_capture_action() {
            for capture in &captures {
                let capture_substring = &input[capture.offset..capture.offset + capture.length];
                let key = capture.group.to_string();
                t.collections.tx.set(key.as_bytes(), capture_substring.to_vec());
                crate::ms_dbg_a!(
                    t,
                    7,
                    "Added regex subexpression TX.{}: {}",
                    capture.group,
                    String::from_utf8_lossy(capture_substring)
                );
                t.matched.push(capture_substring.to_vec());
            }
        }

        for capture in &captures {
            log_offset(rm, capture.offset, capture.length);
        }

        Some(!captures.is_empty())
    }
}

impl Operator for Rx {
    fn name(&self) -> &'static str {
        "Rx"
    }

    fn param(&self) -> Option<&Param> {
        Some(&self.param)
    }

    fn init(&mut self, _file: &str) -> Result<(), String> {
        if !self.contains_macro() {
            let re = Regex::with_options(&self.param.literal, false, MULTI_LINE);
            let has_error = re.has_error();
            self.re = Some(re);
            if has_error {
                return Err(format!("Invalid regular expression: {}", String::from_utf8_lossy(&self.param.literal)));
            }
        }
        Ok(())
    }

    fn evaluate(
        &self,
        t: &mut Transaction<'_>,
        rule: &RuleWithActions,
        input: &[u8],
        rm: &mut RuleMessage<'_>,
    ) -> bool {
        self.try_match(t, rule, input, rm).unwrap_or(false)
    }

    /// A failed regular expression does not match, negated or not (#3123).
    fn evaluate_negatable(
        &self,
        negated: bool,
        t: &mut Transaction<'_>,
        rule: &RuleWithActions,
        input: &[u8],
        rm: &mut RuleMessage<'_>,
    ) -> bool {
        self.try_match(t, rule, input, rm).is_some_and(|matched| matched != negated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operators::operator::test_support::eval;

    #[test]
    fn empty_input_and_captures() {
        let mut op = Rx::new(RunTimeString::from_text("a(b)?c"));
        op.init("").unwrap();
        assert!(!eval(&op, b""));
        assert!(eval(&op, b"xac"));
        let mut bad = Rx::new(RunTimeString::from_text("("));
        assert_eq!(bad.init("").unwrap_err(), "Invalid regular expression: (");
    }
}
