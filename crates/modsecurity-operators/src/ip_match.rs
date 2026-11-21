//! The `@ipMatch` operator: matches when the input is an IP address in one
//! of the listed addresses or networks.

use crate::ip_set::IpSet;
use crate::{Context, Operator, Param};

#[derive(Debug)]
pub struct IpMatch {
    name: &'static str,
    param: Param,
    tree: IpSet,
}

impl IpMatch {
    pub fn new(param: Param) -> Result<Self, String> {
        let mut tree = IpSet::new();
        // An invalid list fails without a message.
        if !tree.add_from_buffer(&param.literal) {
            return Err(String::new());
        }
        Ok(Self::with_set("IpMatch", param, tree))
    }

    /// An operator named `name` in messages that matches the addresses of
    /// `tree`: used by `@ipMatchFromFile` / `@ipMatchF`.
    pub(crate) fn with_set(name: &'static str, param: Param, tree: IpSet) -> Self {
        IpMatch { name, param, tree }
    }
}

impl Operator for IpMatch {
    fn name(&self) -> &'static str {
        self.name
    }

    fn param(&self) -> Option<&Param> {
        Some(&self.param)
    }

    fn evaluate(&self, _cx: &mut dyn Context, input: &[u8]) -> bool {
        self.tree.contains(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::eval;

    #[test]
    fn ip_match() {
        let op = IpMatch::new(Param::from_text("127.0.0.1,192.168.0.0/24,::1")).unwrap();
        assert!(eval(&op, b"127.0.0.1"));
        assert!(eval(&op, b"192.168.0.77"));
        assert!(!eval(&op, b"192.168.1.77"));
        assert!(eval(&op, b"::1"));
        assert!(!eval(&op, b"localhost"));
        assert_eq!(IpMatch::new(Param::from_text("300.1.1.1")).unwrap_err(), "");
    }
}
