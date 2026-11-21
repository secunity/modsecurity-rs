//! The `@strmatch` operator: matches when the parameter occurs anywhere in
//! the input.

use crate::needle::Needle;
use crate::{Context, Operator, Param};

#[derive(Debug)]
pub struct StrMatch {
    param: Param,
    needle: Needle,
}

impl StrMatch {
    pub fn new(param: Param) -> Self {
        StrMatch { needle: Needle::new(&param), param: param.expanded_in_message() }
    }
}

impl Operator for StrMatch {
    fn name(&self) -> &'static str {
        "StrMatch"
    }

    fn param(&self) -> Option<&Param> {
        Some(&self.param)
    }
    fn evaluate(&self, cx: &mut dyn Context, input: &[u8]) -> bool {
        let p = cx.param(&self.param);
        self.needle.find(&p, input).is_some()
    }
}
