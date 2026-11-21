//! The `@verifyCPF` operator: finds Brazilian CPF numbers (taxpayer IDs)
//! whose check digits are valid.

use crate::{Context, Operator, Param};
use modsecurity_native::regex::Regex;

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
    param: Param,
    re: Regex,
}

impl VerifyCPF {
    /// Compiles the expression of `param`; a pattern that does not
    /// compile is an error.
    pub fn new(param: Param) -> Result<Self, String> {
        let re = crate::candidates::compile(&param)?;
        Ok(VerifyCPF { param, re })
    }

    /// The value of a hexadecimal digit (0 for any other byte).
    fn convert_to_int(c: u8) -> i32 {
        match c {
            b'0'..=b'9' => i32::from(c - b'0'),
            b'A'..=b'F' => i32::from(c - b'A') + 10,
            b'a'..=b'f' => i32::from(c - b'a') + 10,
            _ => 0,
        }
    }

    /// Whether `cpfnumber` holds a valid CPF: 11 digits, not a known bad
    /// number, and both check digits right.
    pub fn verify(&self, cpfnumber: &[u8]) -> bool {
        const CPF_LEN: usize = 11;
        let mut cpf = [0i32; CPF_LEN];
        let mut s_cpf = [0u8; CPF_LEN];
        let mut i = 0usize;

        for &c in cpfnumber {
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
    fn name(&self) -> &'static str {
        "VerifyCPF"
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
            crate::ms_dbg!(cx, 7, "Added VerifyCPF match TX.0: {}", String::from_utf8_lossy(&number));
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
        assert_eq!(VerifyCPF::new(Param::from_text("(")).unwrap_err(), "Invalid regular expression: (");
    }

    #[test]
    fn cpf() {
        let op = VerifyCPF::new(Param::from_text("x")).unwrap();
        assert!(op.verify(b"529.982.247-25"));
        assert!(!op.verify(b"529.982.247-26"));
        assert!(!op.verify(b"111.111.111-11"));
        assert!(!op.verify(b"5299822472"));
    }

    /// A NUL byte is a byte like any other: the digits after it count.
    #[test]
    fn nul_byte_in_a_candidate() {
        let op = VerifyCPF::new(Param::from_text("x")).unwrap();
        assert!(op.verify(b"529.982\0.247-25"));
        assert!(!op.verify(b"529.982\0.247-26"));
    }
}
