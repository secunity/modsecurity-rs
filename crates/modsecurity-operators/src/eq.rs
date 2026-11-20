//! The `@eq` operator: matches when the input and the parameter, read as
//! integers, are equal.

use modsecurity_compat::cnum::atoll;

use crate::{Context, Operator, Param};

#[derive(Debug)]
pub struct Eq {
    param: Param,
}

impl Eq {
    pub fn new(param: Param) -> Self {
        Eq { param }
    }
}

impl Operator for Eq {
    fn name(&self) -> &'static str {
        "Eq"
    }

    fn param(&self) -> Option<&Param> {
        Some(&self.param)
    }
    fn evaluate(&self, cx: &mut dyn Context, input: &[u8]) -> bool {
        let pt = cx.param(&self.param);
        // Each side counts as the integer it starts with (0 when it starts
        // with none), as for `@gt`, `@ge`, `@lt` and `@le`.
        atoll(&pt) == atoll(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::eval;

    /// `@eq` compares 64 bit integers. (C++ reads both sides with
    /// `std::stoi`, and a number that does not fit an `int` counts as 0:
    /// `@eq 0` matched 99999999999, and `@eq 3000000000` matched anything
    /// that was not a small number.)
    #[test]
    fn numbers_beyond_the_int_range() {
        let eq = |param: &str, input: &str| eval(&Eq::new(Param::from_text(param)), input.as_bytes());
        assert!(eq("15", "15") && eq("15", " 15abc") && !eq("15", "16"));
        assert!(eq("0", "") && eq("0", "text") && eq("0", "0"));
        assert!(!eq("0", "99999999999"));
        assert!(eq("3000000000", "3000000000"));
        assert!(!eq("3000000000", "text") && !eq("3000000000", "4000000000"));
    }
}
