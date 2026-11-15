//! The `@rxGlobal` operator: like `@rx`, but with `capture` it stores the
//! groups of every match, numbered consecutively in `TX`.

use crate::operators::operator::{MatchContext, Operator, Param};
use crate::utils::regex::{Regex, RegexResult, SMatchCapture};

/// Whether patterns are multi-line: `$` only matches at the very end of
/// the subject when built with `MODSEC_REGEX_DOLLAR_ENDONLY` (cargo feature
/// `regex-dollar-endonly`), otherwise the pattern is multi-line.
const MULTI_LINE: bool = !cfg!(feature = "regex-dollar-endonly");

#[derive(Debug)]
pub struct RxGlobal {
    param: Param,
    re: Option<Regex>,
}

impl RxGlobal {
    pub fn new(param: Param) -> Self {
        RxGlobal { param: param.expanded_in_message(), re: None }
    }

    fn contains_macro(&self) -> bool {
        self.param.contains_macro()
    }
}

impl RxGlobal {
    /// Whether `input` matches; `None` when the regular expression failed
    /// (it does not compile, or it hit the match limits), which is neither
    /// a match nor a mismatch.
    fn try_match(&self, cx: &mut MatchContext<'_, '_, '_>, input: &[u8]) -> Option<bool> {
        if self.param.literal.is_empty() && !self.contains_macro() {
            return Some(true);
        }

        let re_owned;
        let re: &Regex = if self.contains_macro() {
            let eparam = cx.param(&self.param);
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
            cx.regex_compile_error(&re.pattern);
            return None;
        }

        // (`utils::regex` guards against dangling empty-slice pointers.)
        let subject: &[u8] = input;
        let mut captures: Vec<SMatchCapture> = Vec::new();
        let match_limit = cx.pcre_match_limit();
        let regex_result = re.search_global(subject, &mut captures, match_limit);

        if regex_result != RegexResult::Ok {
            cx.regex_search_error(&re.pattern, regex_result == RegexResult::ErrorMatchLimit, "rxGlobal");
            return None;
        }

        if cx.captures() {
            for capture in &captures {
                let capture_substring = &input[capture.offset..capture.offset + capture.length];
                let key = capture.group.to_string();
                cx.set_capture(key.as_bytes(), capture_substring.to_vec());
                crate::op_dbg!(
                    cx,
                    7,
                    "Added regex subexpression TX.{}: {}",
                    capture.group,
                    String::from_utf8_lossy(capture_substring)
                );
                cx.matched(capture_substring.to_vec());
            }
        }

        for capture in &captures {
            cx.offset(capture.offset, capture.length);
        }

        Some(!captures.is_empty())
    }
}

impl Operator for RxGlobal {
    fn name(&self) -> &'static str {
        "RxGlobal"
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

    fn evaluate(&self, cx: &mut MatchContext<'_, '_, '_>, input: &[u8]) -> bool {
        self.try_match(cx, input).unwrap_or(false)
    }

    /// A failed regular expression does not match, negated or not (#3123).
    fn evaluate_negatable(&self, negated: bool, cx: &mut MatchContext<'_, '_, '_>, input: &[u8]) -> bool {
        self.try_match(cx, input).is_some_and(|matched| matched != negated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operators::operator::test_support::eval;

    #[test]
    fn empty_input_and_captures() {
        let mut op = RxGlobal::new(Param::from_text("a(b)?c"));
        op.init("").unwrap();
        assert!(!eval(&op, b""));
        assert!(eval(&op, b"xac"));
        let mut bad = RxGlobal::new(Param::from_text("("));
        assert_eq!(bad.init("").unwrap_err(), "Invalid regular expression: (");
    }
}
