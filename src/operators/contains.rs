//! The `@contains` operator: matches when the parameter occurs anywhere in
//! the input.

use crate::operators::operator::{MatchContext, Operator, Param};
use crate::utils::string::find;

#[derive(Debug)]
pub struct Contains {
    param: Param,
}

impl Contains {
    pub fn new(param: Param) -> Self {
        Contains { param }
    }
}

impl Operator for Contains {
    fn name(&self) -> &'static str {
        "Contains"
    }

    fn param(&self) -> Option<&Param> {
        Some(&self.param)
    }
    fn evaluate(&self, cx: &mut MatchContext<'_, '_, '_>, input: &[u8]) -> bool {
        let p = cx.param(&self.param);
        let offset = find(input, &p);

        let contains = offset.is_some();

        if let Some(offset) = offset {
            cx.offset(offset, p.len());
            cx.matched(p.into_owned());
        }

        contains
    }
}
