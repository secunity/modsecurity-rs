//! The `@lt` operator: matches when the input, read as an integer, is
//! less than the parameter.

use crate::operators::eq::atoll;
use crate::operators::operator::{MatchContext, Operator, Param};
use crate::run_time_string::RunTimeString;

#[derive(Debug)]
pub struct Lt {
    param: Param,
}

impl Lt {
    pub fn new(param: RunTimeString) -> Self {
        Lt { param: Param::expanded_in_message(param) }
    }
}

impl Operator for Lt {
    fn name(&self) -> &'static str {
        "Lt"
    }

    fn param(&self) -> Option<&Param> {
        Some(&self.param)
    }
    fn evaluate(&self, cx: &mut MatchContext<'_, '_, '_>, input: &[u8]) -> bool {
        let p = cx.param(&self.param);
        atoll(input) < atoll(&p)
    }
}
