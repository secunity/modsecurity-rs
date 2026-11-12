//! Port of `src/operators/verify_svnr.cc`, `src/operators/verify_svnr.h`
//! (Austrian social security numbers).

use crate::collection::collection::Collection;
use crate::operators::operator::{Operator, Param, log_offset};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;
use crate::utils::regex::Regex;

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
    pub fn new(param: RunTimeString) -> Self {
        let param = Param::new(param);
        let re = Regex::with_options(&param.literal, false, true);
        VerifySVNR { param, re }
    }

    /// `convert_to_int`
    fn convert_to_int(c: u8) -> i32 {
        if c.is_ascii_digit() { i32::from(c - b'0') } else { 0 }
    }

    /// `verify`
    pub fn verify(&self, svnrnumber: &[u8]) -> bool {
        const SVNR_LEN: usize = 10;
        let mut svnr = [0i32; 11];
        let mut s_svnr = [0u8; SVNR_LEN];
        let mut i = 0usize;

        // The C code stops at the first NUL byte.
        for &c in svnrnumber.iter().take_while(|&&c| c != 0) {
            if i < SVNR_LEN && c.is_ascii_digit() {
                s_svnr[i] = c;
                svnr[i] = Self::convert_to_int(c);
                i += 1;
            }
        }

        if i != SVNR_LEN {
            return false;
        }
        // Quirk kept from C++: only the first 10 of the 12 known bad
        // numbers are checked.
        if BAD_SVNR.iter().take(SVNR_LEN).any(|bad| s_svnr == **bad) {
            return false;
        }

        // Laufnummer mit 3, 7, 9
        // Geburtsdatum mit 5, 8, 4, 2, 1, 6
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
                        t.collections.tx_collection.store_or_update_first(b"0", m.str());
                        crate::ms_dbg_a!(t, 7, "Added VerifySVNR match TX.0: {}", String::from_utf8_lossy(m.str()));
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
    fn svnr() {
        let op = VerifySVNR::new(RunTimeString::from_text("x"));
        assert!(op.verify(b"1237 010180"));
        assert!(!op.verify(b"1238 010180"));
        assert!(!op.verify(b"0000000000"));
        assert!(!op.verify(b"123"));
    }
}
