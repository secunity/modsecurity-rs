//! The `@streq` operator: matches when the input equals the parameter.

use crate::operators::operator::{MatchContext, Operator, Param};
use crate::run_time_string::RunTimeString;

#[derive(Debug)]
pub struct StrEq {
    param: Param,
}

impl StrEq {
    pub fn new(param: RunTimeString) -> Self {
        StrEq { param: Param::new(param) }
    }
}

impl Operator for StrEq {
    fn name(&self) -> &'static str {
        "StrEq"
    }

    fn param(&self) -> Option<&Param> {
        Some(&self.param)
    }
    fn evaluate(&self, cx: &mut MatchContext<'_, '_, '_>, input: &[u8]) -> bool {
        let pt = cx.param(&self.param);
        *pt == *input
    }
}
