//! Port of `src/operators/contains_word.cc`, `src/operators/contains_word.h`.

use crate::operators::operator::{Operator, Param, log_offset};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;
use crate::utils::string::{find, find_from};

#[derive(Debug)]
pub struct ContainsWord {
    param: Param,
}

impl ContainsWord {
    pub fn new(param: RunTimeString) -> Self {
        ContainsWord { param: Param::new(param) }
    }

    /// `acceptableChar`: true when `a[pos]` is not an ASCII letter. A
    /// position out of range (including `0 - 1`, which wraps around in
    /// C++) is not acceptable.
    fn acceptable_char(a: &[u8], pos: usize) -> bool {
        if a.len().wrapping_sub(1) < pos {
            return false;
        }
        let ch = a[pos];
        !ch.is_ascii_alphabetic()
    }
}

impl Operator for ContainsWord {
    fn name(&self) -> &'static str {
        "ContainsWord"
    }

    fn param(&self) -> Option<&Param> {
        Some(&self.param)
    }
    fn evaluate(
        &self,
        t: &mut Transaction<'_>,
        _rule: &RuleWithActions,
        input: &[u8],
        rm: &mut RuleMessage<'_>,
    ) -> bool {
        let param_target = self.param.value(t);

        if param_target.is_empty() {
            return true;
        }
        if input.is_empty() {
            return false;
        }
        if input == &*param_target {
            return true;
        }

        let mut pos = find(input, &param_target);
        while let Some(p) = pos {
            if p == 0 && Self::acceptable_char(input, param_target.len()) {
                log_offset(rm, 0, param_target.len());
                return true;
            }
            if p + param_target.len() == input.len() && Self::acceptable_char(input, p.wrapping_sub(1)) {
                log_offset(rm, p, param_target.len());
                return true;
            }
            if Self::acceptable_char(input, p.wrapping_sub(1)) && Self::acceptable_char(input, p + param_target.len()) {
                log_offset(rm, p, param_target.len());
                return true;
            }
            pos = find_from(input, &param_target, p + 1);
        }

        false
    }
}
