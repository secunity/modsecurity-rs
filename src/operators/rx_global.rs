//! Port of `src/operators/rx_global.cc`, `src/operators/rx_global.h`.

use crate::collection::collection::Collection;
use crate::operators::operator::{
    Operator, OperatorBase, log_offset, report_regex_compile_error, report_regex_search_error,
};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;
use crate::utils::regex::{Regex, RegexResult, SMatchCapture};

/// C++ `kRxGlobalMultiLine`: `$` only matches at the very end of the subject when
/// built with `MODSEC_REGEX_DOLLAR_ENDONLY` (cargo feature
/// `regex-dollar-endonly`), otherwise the pattern is multi-line.
const MULTI_LINE: bool = !cfg!(feature = "regex-dollar-endonly");

#[derive(Debug)]
pub struct RxGlobal {
    pub base: OperatorBase,
    re: Option<Regex>,
}

impl RxGlobal {
    pub fn new(param: RunTimeString) -> Self {
        let mut base = OperatorBase::with_string("RxGlobal", param);
        base.could_contain_macro = true;
        RxGlobal { base, re: None }
    }

    fn contains_macro(&self) -> bool {
        self.base.string.as_ref().is_some_and(|s| s.contains_macro())
    }
}

impl Operator for RxGlobal {
    crate::operator_base_accessors!();

    fn init(&mut self, _file: &str) -> Result<(), String> {
        if !self.contains_macro() {
            let re = Regex::with_options(&self.base.param, false, MULTI_LINE);
            let has_error = re.has_error();
            self.re = Some(re);
            if has_error {
                return Err(format!("Invalid regular expression: {}", String::from_utf8_lossy(&self.base.param)));
            }
        }
        Ok(())
    }

    fn evaluate(
        &self,
        t: Option<&mut Transaction<'_>>,
        rule: Option<&RuleWithActions>,
        input: &[u8],
        rm: Option<&mut RuleMessage<'_>>,
    ) -> bool {
        if self.base.param.is_empty() && !self.contains_macro() {
            return true;
        }

        let re_owned;
        let re: &Regex = if self.contains_macro() {
            let eparam = self.base.string.as_ref().map_or_else(Vec::new, |s| s.evaluate(t.as_deref()));
            re_owned = Regex::with_options(&eparam, false, MULTI_LINE);
            &re_owned
        } else if let Some(re) = self.re.as_ref() {
            re
        } else {
            // init() was not called: compile the parameter now.
            re_owned = Regex::with_options(&self.base.param, false, MULTI_LINE);
            &re_owned
        };

        if re.has_error() {
            report_regex_compile_error(t, re);
            // A regex failure is neither a match nor a mismatch. Return the
            // value that the negation in evaluate_internal turns into "no
            // match", so that the negated form does not fire on errors
            // either (#3123).
            return self.base.negation;
        }

        // (`utils::regex` guards against dangling empty-slice pointers.)
        let subject: &[u8] = input;
        let mut captures: Vec<SMatchCapture> = Vec::new();
        let match_limit = match t.as_deref() {
            Some(tr) if tr.rules.properties.pcre_match_limit.set => {
                u64::from(tr.rules.properties.pcre_match_limit.value)
            }
            _ => 0,
        };
        let regex_result = re.search_global(subject, &mut captures, match_limit);

        if regex_result != RegexResult::Ok {
            report_regex_search_error(t, re, regex_result, "rxGlobal");
            // A regex failure is neither a match nor a mismatch (#3123).
            return self.base.negation;
        }

        if let (Some(rule), Some(t)) = (rule, t)
            && rule.has_capture_action()
        {
            for capture in &captures {
                let capture_substring = &input[capture.offset..capture.offset + capture.length];
                let key = capture.group.to_string();
                t.collections.tx_collection.store_or_update_first(key.as_bytes(), capture_substring);
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

        if let Some(rm) = rm {
            for capture in &captures {
                log_offset(rm, capture.offset, capture.length);
            }
        }

        !captures.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_and_captures() {
        let mut op = RxGlobal::new(RunTimeString::from_text("a(b)?c"));
        op.init("").unwrap();
        assert!(!op.evaluate(None, None, b"", None));
        assert!(op.evaluate(None, None, b"xac", None));
        let mut bad = RxGlobal::new(RunTimeString::from_text("("));
        assert_eq!(bad.init("").unwrap_err(), "Invalid regular expression: (");
    }
}
