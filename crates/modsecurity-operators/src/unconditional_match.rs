//! The `@unconditionalMatch` operator: always matches.

use crate::{Context, Operator};

/// Always matches.
#[derive(Debug)]
pub struct UnconditionalMatch;

impl Default for UnconditionalMatch {
    fn default() -> Self {
        Self::new()
    }
}

impl UnconditionalMatch {
    pub fn new() -> Self {
        UnconditionalMatch
    }
}

impl Operator for UnconditionalMatch {
    fn name(&self) -> &'static str {
        "UnconditionalMatch"
    }
    fn evaluate(&self, _cx: &mut dyn Context, _input: &[u8]) -> bool {
        true
    }
}
