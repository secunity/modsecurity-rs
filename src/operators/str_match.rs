//! The `@strmatch` operator: matches when the parameter occurs anywhere in
//! the input.

use crate::operators::operator::{MatchContext, Operator, Param};
use crate::utils::string::find;

#[derive(Debug)]
pub struct StrMatch {
    param: Param,
}

impl StrMatch {
    pub fn new(param: Param) -> Self {
        StrMatch { param: param.expanded_in_message() }
    }
}

impl Operator for StrMatch {
    fn name(&self) -> &'static str {
        "StrMatch"
    }

    fn param(&self) -> Option<&Param> {
        Some(&self.param)
    }
    fn evaluate(&self, cx: &mut MatchContext<'_, '_, '_>, input: &[u8]) -> bool {
        let p = cx.param(&self.param);
        find(input, &p).is_some()
    }
}
