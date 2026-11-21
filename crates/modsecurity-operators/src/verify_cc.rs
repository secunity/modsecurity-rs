//! `@verifyCC`: finds credit card numbers. The pattern is tried at every
//! offset of the input, and a match counts when it passes the Luhn
//! check.

use crate::{Context, Operator, Param};
use modsecurity_native::regex::{Regex, Subject};

#[derive(Debug)]
pub struct VerifyCC {
    param: Param,
    re: Regex,
}

impl VerifyCC {
    pub fn new(param: Param) -> Result<Self, String> {
        // `PCRE2_DOTALL | PCRE2_MULTILINE`; the pattern ends at its first
        // NUL byte.
        // A pattern that does not compile fails without an error message.
        let re = Regex::compile(&param.literal, false, true).map_err(|_| String::new())?;
        Ok(VerifyCC { param, re })
    }

    /// Luhn Mod-10 Method (ISO 2894/ANSI 4.13). Only the
    /// digits of `ccnumber` are considered.
    pub fn luhn_verify(ccnumber: &[u8]) -> bool {
        let mut sum = [0i32; 2];
        let mut odd = 0usize;
        let mut digits = 0;

        // Weighted lookup table which is just a precalculated (i = index):
        //   i*2 + (( (i*2) > 9 ) ? -9 : 0)
        const WTABLE: [i32; 10] = [0, 2, 4, 6, 8, 1, 3, 5, 7, 9];

        // Add up only digits (weighted digits via lookup table) for both
        // odd and even CC numbers to avoid 2 passes.
        for &c in ccnumber {
            if c.is_ascii_digit() {
                let d = usize::from(c - b'0');
                sum[0] += if odd == 0 { WTABLE[d] } else { d as i32 };
                sum[1] += if odd != 0 { WTABLE[d] } else { d as i32 };
                odd = 1 - odd; // alternate weights
                digits += 1;
            }
        }

        // No digits extracted
        if digits == 0 {
            return false;
        }

        // Do a mod 10 on the sum; if the result is zero the card is valid.
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
        let re = &self.re;
        let subject = Subject::new(i);
        for offset in 0..i.len() {
            // If there was no match, then we are done.
            let Some((start, end)) = re.find_at(&subject, offset) else { break };
            if start > end || end > i.len() {
                continue;
            }
            let m = &i[start..end];
            if Self::luhn_verify(m) {
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

                return true;
            }
        }

        false
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
        assert_eq!(VerifyCC::new(Param::from_text("((")).unwrap_err(), "");
    }
}
