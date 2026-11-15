//! The `@le` operator: matches when the input, read as an integer, is
//! less than or equal to the parameter.

use crate::operators::eq::atoll;
use crate::operators::operator::{MatchContext, Operator, Param};

#[derive(Debug)]
pub struct Le {
    param: Param,
}

impl Le {
    pub fn new(param: Param) -> Self {
        Le { param: param.expanded_in_message() }
    }
}

impl Operator for Le {
    fn name(&self) -> &'static str {
        "Le"
    }

    fn param(&self) -> Option<&Param> {
        Some(&self.param)
    }
    fn evaluate(&self, cx: &mut MatchContext<'_, '_, '_>, input: &[u8]) -> bool {
        let p = cx.param(&self.param);
        atoll(input) <= atoll(&p)
    }
}
