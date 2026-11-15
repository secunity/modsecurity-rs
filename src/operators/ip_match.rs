//! The `@ipMatch` operator: matches when the input is an IP address in one
//! of the listed addresses or networks.

use crate::operators::operator::{MatchContext, Operator, Param};
use crate::utils::ip_tree::IpTree;

#[derive(Debug)]
pub struct IpMatch {
    name: &'static str,
    pub(crate) param: Param,
    pub(crate) tree: IpTree,
}

impl IpMatch {
    pub fn new(param: Param) -> Self {
        Self::with_name("IpMatch", param)
    }

    /// An operator named `name` in messages: used by `@ipMatchFromFile` /
    /// `@ipMatchF`.
    pub fn with_name(name: &'static str, param: Param) -> Self {
        IpMatch { name, param, tree: IpTree::new() }
    }
}

impl Operator for IpMatch {
    fn name(&self) -> &'static str {
        self.name
    }

    fn param(&self) -> Option<&Param> {
        Some(&self.param)
    }

    fn init(&mut self, _file: &str) -> Result<(), String> {
        // An invalid list fails without a message, as in C++.
        if self.tree.add_from_buffer(&self.param.literal) { Ok(()) } else { Err(String::new()) }
    }

    fn evaluate(&self, _cx: &mut MatchContext<'_, '_, '_>, input: &[u8]) -> bool {
        self.tree.contains(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operators::operator::test_support::eval;

    #[test]
    fn ip_match() {
        let mut op = IpMatch::new(Param::from_text("127.0.0.1,192.168.0.0/24,::1"));
        op.init("").unwrap();
        assert!(eval(&op, b"127.0.0.1"));
        assert!(eval(&op, b"192.168.0.77"));
        assert!(!eval(&op, b"192.168.1.77"));
        assert!(eval(&op, b"::1"));
        assert!(!eval(&op, b"localhost"));
        let mut bad = IpMatch::new(Param::from_text("300.1.1.1"));
        assert!(bad.init("").is_err());
    }
}
