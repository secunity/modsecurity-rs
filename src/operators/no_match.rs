//! The `@noMatch` operator: never matches.

use crate::operators::operator::{MatchContext, Operator};

/// Never matches.
#[derive(Debug)]
pub struct NoMatch;

impl Default for NoMatch {
    fn default() -> Self {
        Self::new()
    }
}

impl NoMatch {
    pub fn new() -> Self {
        NoMatch
    }
}

impl Operator for NoMatch {
    fn name(&self) -> &'static str {
        "NoMatch"
    }
    fn evaluate(&self, _cx: &mut MatchContext<'_, '_, '_>, _input: &[u8]) -> bool {
        false
    }
}
