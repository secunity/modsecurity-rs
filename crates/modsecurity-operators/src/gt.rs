//! The `@gt` operator: matches when the input, read as an integer, is
//! greater than the parameter.

use crate::{Context, Operator, Param};
use modsecurity_compat::cnum::atoll;

#[derive(Debug)]
pub struct Gt {
    param: Param,
}

impl Gt {
    pub fn new(param: Param) -> Self {
        Gt { param: param.expanded_in_message() }
    }
}

impl Operator for Gt {
    fn name(&self) -> &'static str {
        "Gt"
    }

    fn param(&self) -> Option<&Param> {
        Some(&self.param)
    }
    fn evaluate(&self, cx: &mut dyn Context, input: &[u8]) -> bool {
        let p = cx.param(&self.param);
        atoll(input) > atoll(&p)
    }
}
