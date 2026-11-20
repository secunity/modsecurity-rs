//! `id:N` — the rule id (configuration time).

use crate::actions::action::{Action, Kind};
use crate::rule::Rule;

#[derive(Debug)]
pub struct RuleId {
    name: String,
    rule_id: crate::rule::Id,
}

impl RuleId {
    /// The id `a`: a decimal number, up to the largest unsigned 64 bit
    /// integer.
    pub fn new(name: &str, a: &str) -> Result<Self, String> {
        match crate::rule::id::parse(a) {
            Some(rule_id) => Ok(RuleId { name: name.to_string(), rule_id }),
            None => Err(format!("The input \"{}\" does not seems to be a valid rule id.", a)),
        }
    }
}

impl Action for RuleId {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> Kind {
        Kind::Configuration
    }

    fn configure(&self, rule: &mut Rule) {
        rule.rule_id = self.rule_id;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::block::test_support::{RuleAction, rule};

    fn id(p: &str) -> Result<u64, String> {
        let a = {
            let text = format!("id:{}", p);
            let (name, payload) = crate::actions::action::name_and_payload(&text);
            RuleId::new(name, payload)
        }?;
        Ok(rule(vec![RuleAction::from(a)]).rule_id)
    }

    #[test]
    fn init_and_configure() {
        assert_eq!(id("1234"), Ok(1234));
        assert_eq!(id("'900018'"), Ok(900018));
        assert_eq!(id("0"), Ok(0));
        assert_eq!(id("007"), Ok(7));
        // Every 64 bit integer is itself (C++ reads the id as a floating
        // point number: this one is refused there, 9007199254740992 is not).
        assert_eq!(id("9007199254740993"), Ok(9007199254740993));
        assert_eq!(id("18446744073709551615"), Ok(u64::MAX));
        let err = |s: &str| Err(format!("The input \"{}\" does not seems to be a valid rule id.", s));
        assert_eq!(id("18446744073709551616"), err("18446744073709551616"));
        assert_eq!(id("abc"), err("abc"));
        assert_eq!(id("-1"), err("-1"));
        assert_eq!(id("+1"), err("+1"));
        assert_eq!(id("1.5"), err("1.5"));
        assert_eq!(id("1e3"), err("1e3"));
        assert_eq!(id(" 1"), err(" 1"));
        assert_eq!(id(""), err(""));
    }
}
