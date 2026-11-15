//! The `@validateHash` operator, which always matches.

use crate::operators::operator::{MatchContext, Operator, Param};
use crate::run_time_string::RunTimeString;

/// Not implemented by libmodsecurity either: always matches.
/// Reference: https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual#validateHash
#[derive(Debug)]
pub struct ValidateHash {
    param: Param,
}

impl ValidateHash {
    pub fn new(param: RunTimeString) -> Self {
        ValidateHash { param: Param::new(param) }
    }
}

impl Operator for ValidateHash {
    fn name(&self) -> &'static str {
        "ValidateHash"
    }

    fn param(&self) -> Option<&Param> {
        Some(&self.param)
    }
    fn evaluate(&self, _cx: &mut MatchContext<'_, '_, '_>, _input: &[u8]) -> bool {
        true
    }
}
