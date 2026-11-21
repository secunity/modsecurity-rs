//! The `@rx` operator: matches a PCRE2 regular expression. `@rxGlobal` is
//! the same, but with `capture` it stores the groups of every match,
//! numbered consecutively in `TX`.

use crate::{Context, Operator, Param};
use modsecurity_native::regex::{MatchError, Regex, SMatchCapture};

/// Whether patterns are multi-line: `$` only matches at the very end of
/// the subject when built with `MODSEC_REGEX_DOLLAR_ENDONLY` (cargo feature
/// `regex-dollar-endonly`), otherwise the pattern is multi-line.
const MULTI_LINE: bool = !cfg!(feature = "regex-dollar-endonly");

/// The regular expression of the parameter.
#[derive(Debug)]
enum Pattern {
    /// A parameter without macros, compiled when the operator is built.
    Compiled(Regex),
    /// A parameter with macros: compiled at each evaluation, from the
    /// parameter expanded for the transaction.
    Expanded,
}

/// `@rx` and `@rxGlobal`.
#[derive(Debug)]
pub struct Rx {
    param: Param,
    pattern: Pattern,
    /// `@rxGlobal`: every match is searched, not only the first.
    global: bool,
}

impl Rx {
    /// `@rx`.
    pub fn new(param: Param) -> Result<Self, String> {
        Self::build(param, false)
    }

    /// `@rxGlobal`.
    pub fn global(param: Param) -> Result<Self, String> {
        Self::build(param, true)
    }

    fn build(param: Param, global: bool) -> Result<Self, String> {
        let pattern = if param.contains_macro() {
            Pattern::Expanded
        } else {
            let re = Regex::compile(&param.literal, false, MULTI_LINE)
                .map_err(|_| format!("Invalid regular expression: {}", String::from_utf8_lossy(&param.literal)))?;
            Pattern::Compiled(re)
        };
        Ok(Rx { param: param.expanded_in_message(), pattern, global })
    }

    /// Whether `input` matches; `None` when the regular expression failed
    /// (it does not compile, or it hit the match limits), which is neither
    /// a match nor a mismatch.
    fn try_match(&self, cx: &mut dyn Context, input: &[u8]) -> Option<bool> {
        let re_owned;
        let re = match &self.pattern {
            // An empty expression matches everything.
            Pattern::Compiled(_) if self.param.literal.is_empty() => return Some(true),
            Pattern::Compiled(re) => re,
            Pattern::Expanded => {
                let eparam = cx.param(&self.param);
                re_owned = Regex::compile(&eparam, false, MULTI_LINE);
                match &re_owned {
                    Ok(re) => re,
                    Err(e) => {
                        cx.regex_compile_error(&e.pattern);
                        return None;
                    }
                }
            }
        };

        // (`modsecurity_native::regex` guards against dangling empty-slice pointers.)
        let subject: &[u8] = input;
        let mut captures: Vec<SMatchCapture> = Vec::new();
        let match_limit = cx.pcre_match_limit();
        let searched = if self.global {
            re.search_global(subject, &mut captures, match_limit)
        } else {
            re.search_one_match(subject, &mut captures, match_limit)
        };
        if let Err(e) = searched {
            let op_name = if self.global { "rxGlobal" } else { "rx" };
            cx.regex_search_error(&re.pattern, e == MatchError::MatchLimit, op_name);
            return None;
        }

        if cx.captures() {
            for capture in &captures {
                let capture_substring = &input[capture.offset..capture.offset + capture.length];
                let key = capture.group.to_string();
                cx.set_capture(key.as_bytes(), capture_substring.to_vec());
                crate::ms_dbg!(
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

impl Operator for Rx {
    fn name(&self) -> &'static str {
        if self.global { "RxGlobal" } else { "Rx" }
    }

    fn param(&self) -> Option<&Param> {
        Some(&self.param)
    }

    fn evaluate(&self, cx: &mut dyn Context, input: &[u8]) -> bool {
        self.try_match(cx, input).unwrap_or(false)
    }

    /// A failed regular expression does not match, negated or not (#3123).
    fn evaluate_negatable(&self, negated: bool, cx: &mut dyn Context, input: &[u8]) -> bool {
        self.try_match(cx, input).is_some_and(|matched| matched != negated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{TestContext, eval};

    #[test]
    fn empty_input_and_captures() {
        let op = Rx::new(Param::from_text("a(b)?c")).unwrap();
        assert_eq!(op.name(), "Rx");
        assert!(!eval(&op, b""));
        assert!(eval(&op, b"xac"));
        assert_eq!(Rx::new(Param::from_text("(")).unwrap_err(), "Invalid regular expression: (");
    }

    #[test]
    fn global_empty_input_and_captures() {
        let op = Rx::global(Param::from_text("a(b)?c")).unwrap();
        assert_eq!(op.name(), "RxGlobal");
        assert!(!eval(&op, b""));
        assert!(eval(&op, b"xac"));
        assert_eq!(Rx::global(Param::from_text("(")).unwrap_err(), "Invalid regular expression: (");
    }

    /// `@rx` records the first match, `@rxGlobal` every match.
    #[test]
    fn first_match_or_every_match() {
        let matched = |op: Rx| {
            let mut cx = TestContext::default();
            assert!(op.evaluate(&mut cx, b"a1 a2"));
            cx.matched
        };
        assert_eq!(matched(Rx::new(Param::from_text("a\\d")).unwrap()), [b"a1".to_vec()]);
        assert_eq!(matched(Rx::global(Param::from_text("a\\d")).unwrap()), [b"a1".to_vec(), b"a2".to_vec()]);
    }

    /// With a macro nothing is compiled when the operator is built, and an
    /// expression that does not compile at evaluation matches nothing,
    /// negated or not. (The test context expands a parameter to its
    /// literal.)
    #[test]
    fn parameter_with_macro() {
        let op = Rx::new(Param::new(b"(".to_vec(), true)).unwrap();
        let mut cx = TestContext::default();
        assert!(!op.evaluate(&mut cx, b"("));
        assert!(!op.evaluate_negatable(false, &mut cx, b"("));
        assert!(!op.evaluate_negatable(true, &mut cx, b"("));

        let op = Rx::global(Param::new(b"a+".to_vec(), true)).unwrap();
        assert!(eval(&op, b"xaa"));
        assert!(op.evaluate_negatable(true, &mut cx, b"x"));
    }

    #[test]
    fn empty_parameter_always_matches() {
        assert!(eval(&Rx::new(Param::from_text("")).unwrap(), b"anything"));
        assert!(eval(&Rx::global(Param::from_text("")).unwrap(), b""));
    }
}
