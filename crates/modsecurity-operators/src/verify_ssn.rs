//! The `@verifySSN` operator: finds plausible US social security numbers.

use crate::{Context, Operator, Param};
use modsecurity_native::regex::Regex;

#[derive(Debug)]
pub struct VerifySSN {
    param: Param,
    re: Regex,
}

impl VerifySSN {
    /// Compiles the expression of `param`; a pattern that does not
    /// compile is an error.
    pub fn new(param: Param) -> Result<Self, String> {
        let re = crate::candidates::compile(&param)?;
        Ok(VerifySSN { param, re })
    }

    /// Whether `ssnumber` is a plausible SSN: nine digits, not all
    /// sequential or repeated, no zero area, group or serial, and an area
    /// below 740 other than 666.
    pub fn verify(&self, ssnumber: &[u8]) -> bool {
        let mut num = [0i32; 9];
        let mut digits = 0usize;

        for &c in ssnumber {
            if c.is_ascii_digit() {
                if digits < 9 {
                    num[digits] = i32::from(c - b'0');
                }
                digits += 1;
            }
        }

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

        // Nine digits in sequence or all the same are not an SSN.
        if sequencial == 8 || repetitions == 8 {
            return false;
        }

        let area = num[0] * 100 + num[1] * 10 + num[2];
        let grp = num[3] * 10 + num[4];
        let serial = num[5] * 1000 + num[6] * 100 + num[7] * 10 + num[8];

        // No part is all zeros.
        if area == 0 || serial == 0 || grp == 0 {
            return false;
        }

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
    fn evaluate(&self, cx: &mut dyn Context, input: &[u8]) -> bool {
        if self.param.literal.is_empty() {
            return false;
        }

        let Some((offset, number)) = crate::candidates::first_verified_in_a_suffix(&self.re, input, |m| self.verify(m))
        else {
            return false;
        };
        cx.offset(offset, number.len());
        if cx.captures() {
            crate::ms_dbg!(cx, 7, "Added VerifySSN match TX.0: {}", String::from_utf8_lossy(&number));
            cx.set_capture(b"0", number);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pattern that does not compile is a configuration error.
    #[test]
    fn invalid_pattern() {
        assert_eq!(VerifySSN::new(Param::from_text("(")).unwrap_err(), "Invalid regular expression: (");
    }

    #[test]
    fn ssn() {
        let op = VerifySSN::new(Param::from_text("x")).unwrap();
        assert!(op.verify(b"078-05-1120"));
        assert!(!op.verify(b"123-45-6789"));
        assert!(!op.verify(b"111-11-1111"));
        assert!(!op.verify(b"666-12-1234"));
        assert!(!op.verify(b"000-12-1234"));
        assert!(!op.verify(b"12345678"));
    }
}
