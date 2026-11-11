//! Port of `src/operators/contains_word.cc`, `src/operators/contains_word.h`.

use crate::operators::operator::{Operator, OperatorBase, log_offset};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;
use crate::utils::string::{find, find_from};

#[derive(Debug)]
pub struct ContainsWord {
    pub base: OperatorBase,
}

impl ContainsWord {
    pub fn new(param: RunTimeString) -> Self {
        ContainsWord { base: OperatorBase::with_string("ContainsWord", param) }
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
    crate::operator_base_accessors!();
    fn evaluate(
        &self,
        t: Option<&mut Transaction<'_>>,
        _rule: Option<&RuleWithActions>,
        input: &[u8],
        mut rm: Option<&mut RuleMessage<'_>>,
    ) -> bool {
        let param_target = self.base.string.as_ref().map_or_else(Vec::new, |s| s.evaluate(t.as_deref()));

        if param_target.is_empty() {
            return true;
        }
        if input.is_empty() {
            return false;
        }
        if input == param_target.as_slice() {
            return true;
        }

        let mut pos = find(input, &param_target);
        while let Some(p) = pos {
            if p == 0 && Self::acceptable_char(input, param_target.len()) {
                if let Some(rm) = rm.as_deref_mut() {
                    log_offset(rm, 0, param_target.len());
                }
                return true;
            }
            if p + param_target.len() == input.len() && Self::acceptable_char(input, p.wrapping_sub(1)) {
                if let Some(rm) = rm.as_deref_mut() {
                    log_offset(rm, p, param_target.len());
                }
                return true;
            }
            if Self::acceptable_char(input, p.wrapping_sub(1)) && Self::acceptable_char(input, p + param_target.len()) {
                if let Some(rm) = rm.as_deref_mut() {
                    log_offset(rm, p, param_target.len());
                }
                return true;
            }
            pos = find_from(input, &param_target, p + 1);
        }

        false
    }
}
