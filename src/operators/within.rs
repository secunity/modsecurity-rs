//! The `@within` operator: matches when the input occurs in the parameter
//! (an empty input always matches).

use crate::operators::operator::{MatchContext, Operator, Param};
use crate::run_time_string::RunTimeString;
use crate::utils::string::find;

#[derive(Debug)]
pub struct Within {
    param: Param,
}

impl Within {
    pub fn new(param: RunTimeString) -> Self {
        Within { param: Param::expanded_in_message(param) }
    }
}

impl Operator for Within {
    fn name(&self) -> &'static str {
        "Within"
    }

    fn param(&self) -> Option<&Param> {
        Some(&self.param)
    }
    fn evaluate(&self, cx: &mut MatchContext<'_, '_, '_>, input: &[u8]) -> bool {
        let param_target = cx.param(&self.param);

        if input.is_empty() {
            return true;
        }

        let pos = find(&param_target, input);
        if let Some(pos) = pos {
            cx.offset(pos, input.len());
        }

        pos.is_some()
    }
}
