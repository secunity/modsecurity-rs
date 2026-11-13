//! Port of `src/operators/verify_ssn.cc`, `src/operators/verify_ssn.h`
//! (US social security numbers).

use crate::operators::operator::{Operator, Param, log_offset};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;
use crate::utils::regex::Regex;

#[derive(Debug)]
pub struct VerifySSN {
    param: Param,
    re: Regex,
}

impl VerifySSN {
    pub fn new(param: RunTimeString) -> Self {
        let param = Param::new(param);
        let re = Regex::with_options(&param.literal, false, true);
        VerifySSN { param, re }
    }

    /// `convert_to_int`
    fn convert_to_int(c: u8) -> i32 {
        match c {
            b'0'..=b'9' => i32::from(c - b'0'),
            b'A'..=b'F' => i32::from(c - b'A') + 10,
            b'a'..=b'f' => i32::from(c - b'a') + 10,
            _ => 0,
        }
    }

    /// `verify`
    pub fn verify(&self, ssnumber: &[u8]) -> bool {
        let mut num = [0i32; 9];
        let mut digits = 0usize;

        for &c in ssnumber {
            if c.is_ascii_digit() {
                if digits < 9 {
                    num[digits] = Self::convert_to_int(c);
                }
                digits += 1;
            }
        }

        // Not a valid number
        if digits != 9 {
            return false;
        }

        let mut sequencial = 0;
        let mut repetitions = 0;
        for i in 0..8 {
            if num[i] == num[i + 1] - 1 {
                sequencial += 1;
            }
            if num[i] == num[i + 1] {
                repetitions += 1;
            }
        }

        // We are blocking when all numbers were sequential or repeated
        if sequencial == 8 || repetitions == 8 {
            return false;
        }

        let area = num[0] * 100 + num[1] * 10 + num[2];
        let grp = num[3] * 10 + num[4];
        let serial = num[5] * 1000 + num[6] * 100 + num[7] * 10 + num[8];

        // Cannot have zeroed fields
        if area == 0 || serial == 0 || grp == 0 {
            return false;
        }

        // More tests
        if area >= 740 || area == 666 {
            return false;
        }

        true
    }
}

impl Operator for VerifySSN {
    fn name(&self) -> &'static str {
        "VerifySSN"
    }

    fn param(&self) -> Option<&Param> {
        Some(&self.param)
    }
    fn evaluate(
        &self,
        t: &mut Transaction<'_>,
        rule: &RuleWithActions,
        input: &[u8],
        rm: &mut RuleMessage<'_>,
    ) -> bool {
        if self.param.literal.is_empty() {
            return false;
        }

        let mut i = 0usize;
        while i + 1 < input.len() {
            // Offsets are relative to the searched suffix, as in C++.
            let matches = self.re.search_all(&input[i..]);
            for m in &matches {
                if self.verify(m.str()) {
                    log_offset(rm, m.offset(), m.str().len());
                    if rule.has_capture_action() {
                        t.collections.tx.set(b"0", m.str().to_vec());
                        crate::ms_dbg_a!(t, 7, "Added VerifySSN match TX.0: {}", String::from_utf8_lossy(m.str()));
                    }
                    return true;
                }
            }
            i += 1;
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssn() {
        let op = VerifySSN::new(RunTimeString::from_text("x"));
        assert!(op.verify(b"078-05-1120"));
        assert!(!op.verify(b"123-45-6789"));
        assert!(!op.verify(b"111-11-1111"));
        assert!(!op.verify(b"666-12-1234"));
        assert!(!op.verify(b"000-12-1234"));
        assert!(!op.verify(b"12345678"));
    }
}
