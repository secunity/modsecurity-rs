//! The `@verifySVNR` operator: finds Austrian social security numbers
//! whose check digit is valid.

use crate::{Context, Operator, Param};
use modsecurity_native::regex::Regex;

const BAD_SVNR: [&[u8; 10]; 12] = [
    b"0000000000",
    b"0123456789",
    b"1234567890",
    b"1111111111",
    b"2222222222",
    b"3333333333",
    b"4444444444",
    b"5555555555",
    b"6666666666",
    b"7777777777",
    b"8888888888",
    b"9999999999",
];

#[derive(Debug)]
pub struct VerifySVNR {
    param: Param,
    re: Regex,
}

impl VerifySVNR {
    /// Compiles the expression of `param`; a pattern that does not
    /// compile is an error.
    pub fn new(param: Param) -> Result<Self, String> {
        let re = crate::candidates::compile(&param)?;
        Ok(VerifySVNR { param, re })
    }

    /// Whether `svnrnumber` holds a valid SVNR: 10 digits, not a known bad
    /// number, and the check digit right.
    pub fn verify(&self, svnrnumber: &[u8]) -> bool {
        const SVNR_LEN: usize = 10;
        let mut svnr = [0i32; 11];
        let mut s_svnr = [0u8; SVNR_LEN];
        let mut i = 0usize;

        for &c in svnrnumber {
            if i < SVNR_LEN && c.is_ascii_digit() {
                s_svnr[i] = c;
                svnr[i] = i32::from(c - b'0');
                i += 1;
            }
        }

        if i != SVNR_LEN {
            return false;
        }
        if BAD_SVNR.iter().any(|bad| s_svnr == **bad) {
            return false;
        }

        // The weights: 3, 7, 9 for the serial number (the first three
        // digits) and 5, 8, 4, 2, 1, 6 for the date of birth (the last six);
        // the fourth digit is the check digit.
        let mut sum = svnr[0] * 3
            + svnr[1] * 7
            + svnr[2] * 9
            + svnr[4] * 5
            + svnr[5] * 8
            + svnr[6] * 4
            + svnr[7] * 2
            + svnr[8]
            + svnr[9] * 6;
        sum %= 11;
        if sum == 10 {
            sum = 0;
        }
        sum == svnr[3]
    }
}

impl Operator for VerifySVNR {
    fn name(&self) -> &'static str {
        "VerifySVNR"
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
            crate::ms_dbg!(cx, 7, "Added VerifySVNR match TX.0: {}", String::from_utf8_lossy(&number));
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
        assert_eq!(VerifySVNR::new(Param::from_text("(")).unwrap_err(), "Invalid regular expression: (");
    }

    #[test]
    fn svnr() {
        let op = VerifySVNR::new(Param::from_text("x")).unwrap();
        assert!(op.verify(b"1237 010180"));
        assert!(!op.verify(b"1238 010180"));
        assert!(!op.verify(b"0000000000"));
        assert!(!op.verify(b"123"));
    }

    /// Every known bad number is refused, the last two included (their
    /// check digit is right).
    #[test]
    fn known_bad_numbers() {
        let op = VerifySVNR::new(Param::from_text("x")).unwrap();
        for bad in BAD_SVNR {
            assert!(!op.verify(bad), "{}", String::from_utf8_lossy(bad));
        }
        assert!(!op.verify(b"8888888888"));
        assert!(!op.verify(b"9999 999999"));
        let op = VerifySVNR::new(Param::from_text(r"\d{4} ?\d{6}")).unwrap();
        assert!(!crate::test_support::eval(&op, b"svnr: 8888888888"));
        assert!(crate::test_support::eval(&op, b"svnr: 1237 010180"));
    }

    /// A NUL byte is a byte like any other: the digits after it count.
    #[test]
    fn nul_byte_in_a_candidate() {
        let op = VerifySVNR::new(Param::from_text("x")).unwrap();
        assert!(op.verify(b"1237\x00010180"));
        assert!(!op.verify(b"1238\x00010180"));
    }
}
