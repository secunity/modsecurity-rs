//! The `@containsWord` operator: matches when the parameter occurs in the
//! input as a whole word, not next to an ASCII letter.

use crate::{Context, Operator, Param};
use modsecurity_compat::chars::{find, find_from};

#[derive(Debug)]
pub struct ContainsWord {
    param: Param,
}

impl ContainsWord {
    pub fn new(param: Param) -> Self {
        ContainsWord { param }
    }

    /// Whether `a[pos]` can border a word: true when it is not an ASCII
    /// letter. A position out of range (including the one before position
    /// 0, which callers pass as `0.wrapping_sub(1)`) is not acceptable.
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
    fn evaluate(&self, cx: &mut dyn Context, input: &[u8]) -> bool {
        let param_target = cx.param(&self.param);

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
                cx.offset(0, param_target.len());
                return true;
            }
            if p + param_target.len() == input.len() && Self::acceptable_char(input, p.wrapping_sub(1)) {
                cx.offset(p, param_target.len());
                return true;
            }
            if Self::acceptable_char(input, p.wrapping_sub(1)) && Self::acceptable_char(input, p + param_target.len()) {
                cx.offset(p, param_target.len());
                return true;
            }
            pos = find_from(input, &param_target, p + 1);
        }

        false
    }
}
