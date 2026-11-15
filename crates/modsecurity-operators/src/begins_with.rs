//! The `@beginsWith` operator: matches when the input starts with the
//! parameter.

use crate::{Context, Operator, Param};

#[derive(Debug)]
pub struct BeginsWith {
    param: Param,
}

impl BeginsWith {
    pub fn new(param: Param) -> Self {
        BeginsWith { param }
    }
}

impl Operator for BeginsWith {
    fn name(&self) -> &'static str {
        "BeginsWith"
    }

    fn param(&self) -> Option<&Param> {
        Some(&self.param)
    }
    fn evaluate(&self, cx: &mut dyn Context, input: &[u8]) -> bool {
        let p = cx.param(&self.param);

        if input.len() < p.len() {
            false
        } else if input.starts_with(&p) {
            cx.offset(0, p.len());
            true
        } else {
            false
        }
    }
}
