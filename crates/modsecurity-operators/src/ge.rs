//! The `@ge` operator: matches when the input, read as an integer, is
//! greater than or equal to the parameter.

use crate::eq::atoll;
use crate::{Context, Operator, Param};

#[derive(Debug)]
pub struct Ge {
    param: Param,
}

impl Ge {
    pub fn new(param: Param) -> Self {
        Ge { param: param.expanded_in_message() }
    }
}

impl Operator for Ge {
    fn name(&self) -> &'static str {
        "Ge"
    }

    fn param(&self) -> Option<&Param> {
        Some(&self.param)
    }
    fn evaluate(&self, cx: &mut dyn Context, input: &[u8]) -> bool {
        let p = cx.param(&self.param);
        atoll(input) >= atoll(&p)
    }
}
