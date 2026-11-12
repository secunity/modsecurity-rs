//! Port of `src/operators/verify_cpf.cc`, `src/operators/verify_cpf.h`
//! (Brazilian CPF numbers).

use crate::collection::collection::Collection;
use crate::operators::operator::{Operator, OperatorBase, log_offset};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;
use crate::utils::regex::Regex;

const BAD_CPF: [&[u8; 11]; 11] = [
    b"00000000000",
    b"01234567890",
    b"11111111111",
    b"22222222222",
    b"33333333333",
    b"44444444444",
    b"55555555555",
    b"66666666666",
    b"77777777777",
    b"88888888888",
    b"99999999999",
];

#[derive(Debug)]
pub struct VerifyCPF {
    pub base: OperatorBase,
    re: Regex,
}

impl VerifyCPF {
    pub fn new(param: RunTimeString) -> Self {
        let base = OperatorBase::with_string("VerifyCPF", param);
        let re = Regex::with_options(&base.param, false, true);
        VerifyCPF { base, re }
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

    /// `verify`: checks the two CPF check digits.
    pub fn verify(&self, cpfnumber: &[u8]) -> bool {
        const CPF_LEN: usize = 11;
        let mut cpf = [0i32; CPF_LEN];
        let mut s_cpf = [0u8; CPF_LEN];
        let mut i = 0usize;

        // The C code stops at the first NUL byte.
        for &c in cpfnumber.iter().take_while(|&&c| c != 0) {
            if i < CPF_LEN && c.is_ascii_digit() {
                s_cpf[i] = c;
                cpf[i] = Self::convert_to_int(c);
                i += 1;
            }
        }

        if i != CPF_LEN {
            return false;
        }
        if BAD_CPF.iter().any(|bad| s_cpf == **bad) {
            return false;
        }

        let part_1 = Self::convert_to_int(s_cpf[CPF_LEN - 2]);
        let part_2 = Self::convert_to_int(s_cpf[CPF_LEN - 1]);

        let mut sum: i32 = 0;
        let mut c = CPF_LEN as i32;
        for d in cpf.iter().take(9) {
            c -= 1;
            sum += d * c;
        }
        let factor = sum % CPF_LEN as i32;
        cpf[9] = if factor < 2 { 0 } else { CPF_LEN as i32 - factor };

        sum = 0;
        c = CPF_LEN as i32;
        for d in cpf.iter().take(10) {
            sum += d * c;
            c -= 1;
        }
        let factor = sum % CPF_LEN as i32;
        cpf[10] = if factor < 2 { 0 } else { CPF_LEN as i32 - factor };

        part_1 == cpf[9] && part_2 == cpf[10]
    }
}

impl Operator for VerifyCPF {
    crate::operator_base_accessors!();
    fn evaluate(
        &self,
        t: &mut Transaction<'_>,
        rule: &RuleWithActions,
        input: &[u8],
        rm: &mut RuleMessage<'_>,
    ) -> bool {
        if self.base.param.is_empty() {
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
                        crate::ms_dbg_a!(t, 7, "Added VerifyCPF match TX.0: {}", String::from_utf8_lossy(m.str()));
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
    fn cpf() {
        let op = VerifyCPF::new(RunTimeString::from_text("x"));
        assert!(op.verify(b"529.982.247-25"));
        assert!(!op.verify(b"529.982.247-26"));
        assert!(!op.verify(b"111.111.111-11"));
        assert!(!op.verify(b"5299822472"));
    }
}
