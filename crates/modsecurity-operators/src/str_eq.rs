//! The `@streq` operator: matches when the input equals the parameter.

use crate::{Context, Operator, Param};

#[derive(Debug)]
pub struct StrEq {
    param: Param,
}

impl StrEq {
    pub fn new(param: Param) -> Self {
        StrEq { param }
    }
}

impl Operator for StrEq {
    fn name(&self) -> &'static str {
        "StrEq"
    }

    fn param(&self) -> Option<&Param> {
        Some(&self.param)
    }
    fn evaluate(&self, cx: &mut dyn Context, input: &[u8]) -> bool {
        let pt = cx.param(&self.param);
        *pt == *input
    }
}
