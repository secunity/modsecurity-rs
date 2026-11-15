//! The `@lt` operator: matches when the input, read as an integer, is
//! less than the parameter.

use crate::{Context, Operator, Param};
use modsecurity_compat::cnum::atoll;

#[derive(Debug)]
pub struct Lt {
    param: Param,
}

impl Lt {
    pub fn new(param: Param) -> Self {
        Lt { param: param.expanded_in_message() }
    }
}

impl Operator for Lt {
    fn name(&self) -> &'static str {
        "Lt"
    }

    fn param(&self) -> Option<&Param> {
        Some(&self.param)
    }
    fn evaluate(&self, cx: &mut dyn Context, input: &[u8]) -> bool {
        let p = cx.param(&self.param);
        atoll(input) < atoll(&p)
    }
}
