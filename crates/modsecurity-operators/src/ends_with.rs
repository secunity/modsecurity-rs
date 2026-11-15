//! The `@endsWith` operator: matches when the input ends with the
//! parameter.

use crate::{Context, Operator, Param};

#[derive(Debug)]
pub struct EndsWith {
    param: Param,
}

impl EndsWith {
    pub fn new(param: Param) -> Self {
        EndsWith { param: param.expanded_in_message() }
    }
}

impl Operator for EndsWith {
    fn name(&self) -> &'static str {
        "EndsWith"
    }

    fn param(&self) -> Option<&Param> {
        Some(&self.param)
    }
    fn evaluate(&self, cx: &mut dyn Context, input: &[u8]) -> bool {
        let mut ret = false;
        let p = cx.param(&self.param);

        if input.len() >= p.len() {
            ret = input.ends_with(&p);
            if ret {
                cx.offset(input.len() - p.len(), p.len());
            }
        }

        ret
    }
}
