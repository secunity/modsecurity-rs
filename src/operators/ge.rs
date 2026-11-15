//! The `@ge` operator: matches when the input, read as an integer, is
//! greater than or equal to the parameter.

use crate::operators::eq::atoll;
use crate::operators::operator::{MatchContext, Operator, Param};
use crate::run_time_string::RunTimeString;

#[derive(Debug)]
pub struct Ge {
    param: Param,
}

impl Ge {
    pub fn new(param: RunTimeString) -> Self {
        Ge { param: Param::expanded_in_message(param) }
    }
}

impl Operator for Ge {
    fn name(&self) -> &'static str {
        "Ge"
    }

    fn param(&self) -> Option<&Param> {
        Some(&self.param)
    }
    fn evaluate(&self, cx: &mut MatchContext<'_, '_, '_>, input: &[u8]) -> bool {
        let p = cx.param(&self.param);
        atoll(input) >= atoll(&p)
    }
}
