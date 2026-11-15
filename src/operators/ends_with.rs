//! The `@endsWith` operator: matches when the input ends with the
//! parameter.

use crate::operators::operator::{MatchContext, Operator, Param};
use crate::run_time_string::RunTimeString;

#[derive(Debug)]
pub struct EndsWith {
    param: Param,
}

impl EndsWith {
    pub fn new(param: RunTimeString) -> Self {
        EndsWith { param: Param::expanded_in_message(param) }
    }
}

impl Operator for EndsWith {
    fn name(&self) -> &'static str {
        "EndsWith"
    }

    fn param(&self) -> Option<&Param> {
        Some(&self.param)
    }
    fn evaluate(&self, cx: &mut MatchContext<'_, '_, '_>, input: &[u8]) -> bool {
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
