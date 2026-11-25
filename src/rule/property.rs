//! What an action says about its rule rather than what it does: `id`,
//! `phase`, `rev`, `ver`, `accuracy`, `maturity` and `chain` set a property
//! of the rule when it is built ([`Rule::new`]), and never run.
//! `SecDefaultAction` accepts `phase` alone of them, and
//! `SecRuleUpdateActionById` none.

use crate::phases::Phases;
use crate::rule::{Id, Rule};
use crate::utils::string::parse_digits;

/// A property of a rule, as an action sets it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Property {
    /// `id:N`.
    Id(Id),
    /// `phase:N` (or `request`, `response`, `logging`).
    Phase(Phases),
    /// `rev:'...'`.
    Rev(String),
    /// `ver:'...'`.
    Ver(String),
    /// `accuracy:N`.
    Accuracy(u8),
    /// `maturity:N`.
    Maturity(u8),
    /// `chain`: the rule that comes next in the configuration continues
    /// this one.
    Chain,
}

/// A property and the name of the action that set it, as written in the
/// rule (for the messages that name it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleProperty {
    pub name: String,
    pub property: Property,
}

impl RuleProperty {
    fn new(name: &str, property: Property) -> Self {
        RuleProperty { name: name.to_string(), property }
    }

    /// `id`: a decimal number, up to the largest unsigned 64 bit integer.
    pub fn id(name: &str, payload: &str) -> Result<Self, String> {
        match crate::rule::id::parse(payload) {
            Some(id) => Ok(Self::new(name, Property::Id(id))),
            None => Err(format!("The input \"{}\" does not seems to be a valid rule id.", payload)),
        }
    }

    /// `phase`: a phase number (0 to 5) or `request`, `response` or
    /// `logging`.
    pub fn phase(name: &str, payload: &str) -> Result<Self, String> {
        let phase = match payload.to_ascii_lowercase().as_str() {
            "0" => Phases::Connection,
            "1" => Phases::RequestHeaders,
            "2" | "request" => Phases::RequestBody,
            "3" => Phases::ResponseHeaders,
            "4" | "response" => Phases::ResponseBody,
            "5" | "logging" => Phases::Logging,
            _ => return Err(format!("Unknown phase: {}", payload)),
        };
        Ok(Self::new(name, Property::Phase(phase)))
    }

    pub fn rev(name: &str, payload: &str) -> Self {
        Self::new(name, Property::Rev(payload.to_string()))
    }

    pub fn ver(name: &str, payload: &str) -> Self {
        Self::new(name, Property::Ver(payload.to_string()))
    }

    pub fn accuracy(name: &str, payload: &str) -> Result<Self, String> {
        let accuracy =
            parse_digits(payload).ok_or_else(|| format!("Accuracy: The input \"{}\" is not a number.", payload))?;
        Ok(Self::new(name, Property::Accuracy(accuracy)))
    }

    pub fn maturity(name: &str, payload: &str) -> Result<Self, String> {
        let maturity =
            parse_digits(payload).ok_or_else(|| format!("Maturity: The input \"{}\" is not a number.", payload))?;
        Ok(Self::new(name, Property::Maturity(maturity)))
    }

    pub fn chain(name: &str) -> Self {
        Self::new(name, Property::Chain)
    }

    /// Sets the property of `rule`; a later one replaces an earlier one.
    pub(super) fn apply(&self, rule: &mut Rule) {
        match &self.property {
            Property::Id(id) => rule.rule_id = Some(*id),
            Property::Phase(phase) => rule.set_phase(*phase),
            Property::Rev(rev) => rule.metadata.rev.clone_from(rev),
            Property::Ver(ver) => rule.metadata.ver.clone_from(ver),
            Property::Accuracy(accuracy) => rule.metadata.accuracy = *accuracy,
            Property::Maturity(maturity) => rule.metadata.maturity = *maturity,
            Property::Chain => rule.chain.continued = true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::RuleKind;

    /// A `SecAction` with these properties.
    fn rule(properties: Vec<RuleProperty>) -> Rule {
        Rule::new(properties, None, None, "test.conf", 1, RuleKind::SecAction)
    }

    /// The property of `action` (`name:payload`), as `build` makes it.
    fn parsed(action: &str, build: fn(&str, &str) -> Result<RuleProperty, String>) -> Result<RuleProperty, String> {
        let (name, payload) = crate::actions::action::name_and_payload(action);
        build(name, payload)
    }

    fn id(p: &str) -> Result<Option<u64>, String> {
        let p = parsed(&format!("id:{p}"), RuleProperty::id)?;
        Ok(rule(vec![p]).rule_id)
    }

    fn phase(p: &str) -> Result<Phases, String> {
        let p = parsed(&format!("phase:{p}"), RuleProperty::phase)?;
        Ok(rule(vec![p]).phase())
    }

    #[test]
    fn ids() {
        assert_eq!(id("1234"), Ok(Some(1234)));
        assert_eq!(id("'900018'"), Ok(Some(900018)));
        assert_eq!(id("0"), Ok(Some(0)));
        assert_eq!(id("007"), Ok(Some(7)));
        // Every 64 bit integer is itself (C++ reads the id as a floating
        // point number: this one is refused there, 9007199254740992 is not).
        assert_eq!(id("9007199254740993"), Ok(Some(9007199254740993)));
        assert_eq!(id("18446744073709551615"), Ok(Some(u64::MAX)));
        let err = |s: &str| Err(format!("The input \"{}\" does not seems to be a valid rule id.", s));
        for bad in ["18446744073709551616", "abc", "-1", "+1", "1.5", "1e3", " 1", ""] {
            assert_eq!(id(bad), err(bad), "{bad:?}");
        }
    }

    #[test]
    fn phases() {
        assert_eq!(phase("0"), Ok(Phases::Connection));
        assert_eq!(phase("1"), Ok(Phases::RequestHeaders));
        assert_eq!(phase("2"), Ok(Phases::RequestBody));
        assert_eq!(phase("3"), Ok(Phases::ResponseHeaders));
        assert_eq!(phase("4"), Ok(Phases::ResponseBody));
        assert_eq!(phase("5"), Ok(Phases::Logging));
        assert_eq!(phase("REQUEST"), Ok(Phases::RequestBody));
        assert_eq!(phase("response"), Ok(Phases::ResponseBody));
        assert_eq!(phase("logging"), Ok(Phases::Logging));
        assert_eq!([Phases::Connection, Phases::RequestHeaders, Phases::Logging].map(Phases::number), [0, 1, 5]);
        // Anything else is refused. (An unknown name used to be accepted:
        // the rule was in no phase and never ran. C++ does the same, and
        // crashes on a number beyond `int`.)
        for unknown in ["foo", "6", "02", "+2", "2 ", "2147483648", "18446744073709551618", ""] {
            assert_eq!(phase(unknown), Err(format!("Unknown phase: {unknown}")), "{unknown:?}");
        }
    }

    #[test]
    fn metadata_and_chain() {
        let r = rule(vec![
            RuleProperty::accuracy("accuracy", "8").unwrap(),
            RuleProperty::maturity("maturity", "9").unwrap(),
            RuleProperty::rev("rev", "2.1.3"),
            RuleProperty::ver("ver", "CRS/3"),
            RuleProperty::chain("chain"),
        ]);
        assert_eq!(r.metadata.accuracy, 8);
        assert_eq!(r.metadata.maturity, 9);
        assert_eq!(r.metadata.rev, "2.1.3");
        assert_eq!(r.metadata.ver, "CRS/3");
        assert!(r.chain.continued);

        assert_eq!(RuleProperty::accuracy("accuracy", "x").unwrap_err(), "Accuracy: The input \"x\" is not a number.");
        assert_eq!(RuleProperty::maturity("maturity", "").unwrap_err(), "Maturity: The input \"\" is not a number.");
    }

    /// A later property replaces an earlier one; the name is kept as
    /// written.
    #[test]
    fn the_last_one_counts() {
        let r = rule(vec![RuleProperty::id("id", "1").unwrap(), RuleProperty::id("ID", "2").unwrap()]);
        assert_eq!(r.rule_id, Some(2));
        assert_eq!(RuleProperty::chain("Chain").name, "Chain");
    }
}
