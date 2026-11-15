//! The `@gt` operator: matches when the input, read as an integer, is
//! greater than the parameter.

use crate::operators::eq::atoll;
use crate::operators::operator::{MatchContext, Operator, Param};
use crate::run_time_string::RunTimeString;

#[derive(Debug)]
pub struct Gt {
    param: Param,
}

impl Gt {
    pub fn new(param: RunTimeString) -> Self {
        Gt { param: Param::expanded_in_message(param) }
    }
}

impl Operator for Gt {
    fn name(&self) -> &'static str {
        "Gt"
    }

    fn param(&self) -> Option<&Param> {
        Some(&self.param)
    }
    fn evaluate(&self, cx: &mut MatchContext<'_, '_, '_>, input: &[u8]) -> bool {
        let p = cx.param(&self.param);
        atoll(input) > atoll(&p)
    }
}
