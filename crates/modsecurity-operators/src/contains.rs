//! The `@contains` operator: matches when the parameter occurs anywhere in
//! the input.

use crate::needle::Needle;
use crate::{Context, Operator, Param};

#[derive(Debug)]
pub struct Contains {
    param: Param,
    needle: Needle,
}

impl Contains {
    pub fn new(param: Param) -> Self {
        Contains { needle: Needle::new(&param), param }
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
        let offset = self.needle.find(&p, input);

        let contains = offset.is_some();

        if let Some(offset) = offset {
            cx.offset(offset, p.len());
            cx.matched(p.into_owned());
        }

        contains
    }
}
