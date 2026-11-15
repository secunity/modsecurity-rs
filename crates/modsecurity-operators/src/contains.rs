//! The `@contains` operator: matches when the parameter occurs anywhere in
//! the input.

use crate::{Context, Operator, Param};
use modsecurity_compat::chars::find;

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
    fn evaluate(&self, cx: &mut dyn Context, input: &[u8]) -> bool {
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
