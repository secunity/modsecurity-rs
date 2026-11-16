//! The `@validateHash` operator, which always matches.

use crate::{Context, Operator, Param};

/// Not implemented by libmodsecurity either: always matches.
/// Reference: <https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual#validateHash>
#[derive(Debug)]
pub struct ValidateHash {
    param: Param,
}

impl ValidateHash {
    pub fn new(param: Param) -> Self {
        ValidateHash { param }
    }
}

impl Operator for ValidateHash {
    fn name(&self) -> &'static str {
        "ValidateHash"
    }

    fn param(&self) -> Option<&Param> {
        Some(&self.param)
    }
    fn evaluate(&self, _cx: &mut dyn Context, _input: &[u8]) -> bool {
        true
    }
}
