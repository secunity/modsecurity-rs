//! `@verifyCC`: finds credit card numbers. The pattern is tried at every
//! offset of the input, and a match counts when it passes the Luhn
//! check.

use crate::{Context, Operator, Param};
use modsecurity_native::regex::Regex;

#[derive(Debug)]
pub struct VerifyCC {
    param: Param,
    re: Regex,
}

impl VerifyCC {
    pub fn new(param: Param) -> Result<Self, String> {
        let re = crate::candidates::compile(&param)?;
        Ok(VerifyCC { param, re })
    }

    /// The Luhn (mod 10) check. Only the digits of `ccnumber` are
    /// considered.
    pub fn luhn_verify(ccnumber: &[u8]) -> bool {
        let mut sum = [0i32; 2];
        let mut odd = 0usize;
        let mut digits = 0;

        // A doubled digit: `2 * d`, minus 9 when that is over 9.
        const WTABLE: [i32; 10] = [0, 2, 4, 6, 8, 1, 3, 5, 7, 9];

        // `sum[0]` doubles the 1st, 3rd, ... digit and `sum[1]` the 2nd,
        // 4th, ...: which one is the Luhn sum depends on whether the number
        // of digits is even, known only at the end, so both are kept to
        // read the input once.
        for &c in ccnumber {
            if c.is_ascii_digit() {
                let d = usize::from(c - b'0');
                sum[0] += if odd == 0 { WTABLE[d] } else { d as i32 };
                sum[1] += if odd != 0 { WTABLE[d] } else { d as i32 };
                odd = 1 - odd; // alternate weights
                digits += 1;
            }
        }

        if digits == 0 {
            return false;
        }

        // `sum[odd]` is the sum that does not double the last digit; the
        // number is valid when it is a multiple of 10.
        sum[odd] % 10 == 0
    }
}

impl Operator for VerifyCC {
    fn name(&self) -> &'static str {
        "VerifyCC"
    }

    fn param(&self) -> Option<&Param> {
        Some(&self.param)
    }

    fn evaluate(&self, cx: &mut dyn Context, i: &[u8]) -> bool {
        let Some((offset, m)) = crate::candidates::first_verified(&self.re, i, Self::luhn_verify) else {
            return false;
        };
        if cx.captures() {
            cx.set_capture(b"0", m.to_vec());
            crate::ms_dbg!(cx, 7, "Added VerifyCC match TX.0: {}", String::from_utf8_lossy(m));
        }
        crate::ms_dbg!(
            cx,
            9,
            "CC# match \"{}\" at {}. [offset {}]",
            String::from_utf8_lossy(&self.param.literal),
            String::from_utf8_lossy(i),
            offset
        );
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::eval;

    #[test]
    fn luhn() {
        assert!(VerifyCC::luhn_verify(b"4111111111111111"));
        assert!(VerifyCC::luhn_verify(b"4111-1111-1111-1111"));
        assert!(!VerifyCC::luhn_verify(b"4111111111111112"));
        assert!(!VerifyCC::luhn_verify(b"abc"));
        assert!(VerifyCC::luhn_verify(b"0"));
    }

    #[test]
    fn verify_cc() {
        let op = VerifyCC::new(Param::from_text("\\d{13,16}")).unwrap();
        assert!(eval(&op, b"cc: 4111111111111111 x"));
        assert!(!eval(&op, b"cc: 4111111111112 x"));
        assert_eq!(VerifyCC::new(Param::from_text("((")).unwrap_err(), "Invalid regular expression: ((");
    }
}
