//! The `@gsbLookup` operator (Google Safe Browsing lookup), which always
//! matches.

use crate::operators::operator::{MatchContext, Operator, Param};

/// Not implemented by libmodsecurity either: always matches.
/// Reference: https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual#gsblookup
#[derive(Debug)]
pub struct GsbLookup {
    param: Param,
}

impl GsbLookup {
    pub fn new(param: Param) -> Self {
        GsbLookup { param }
    }
}

impl Operator for GsbLookup {
    fn name(&self) -> &'static str {
        "GsbLookup"
    }

    fn param(&self) -> Option<&Param> {
        Some(&self.param)
    }
    fn evaluate(&self, _cx: &mut MatchContext<'_, '_, '_>, _input: &[u8]) -> bool {
        true
    }
}
