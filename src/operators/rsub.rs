//! The `@rsub` operator (regular expression substitution), which always
//! matches.

use crate::operators::operator::{MatchContext, Operator, Param};
use crate::run_time_string::RunTimeString;

/// Not implemented by libmodsecurity either: always matches.
/// Reference: https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual#rsub
#[derive(Debug)]
pub struct Rsub {
    param: Param,
}

impl Rsub {
    pub fn new(param: RunTimeString) -> Self {
        Rsub { param: Param::new(param) }
    }
}

impl Operator for Rsub {
    fn name(&self) -> &'static str {
        "Rsub"
    }

    fn param(&self) -> Option<&Param> {
        Some(&self.param)
    }
    fn evaluate(&self, _cx: &mut MatchContext<'_, '_, '_>, _input: &[u8]) -> bool {
        true
    }
}
