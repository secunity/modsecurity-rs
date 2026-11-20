//! The `@eq` operator: matches when the input and the parameter, read as
//! integers, are equal.

use modsecurity_compat::cnum::stoi;

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
        // A value that `stoi` cannot read counts as 0.
        let p = stoi(&pt).unwrap_or(0);
        let i = stoi(input).unwrap_or(0);
        p == i
    }
}
