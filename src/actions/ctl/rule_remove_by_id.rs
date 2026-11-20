//! `ctl:ruleRemoveById=1 2 100-200` — disables rules (by id or id range)
//! for the rest of the transaction.

use crate::actions::action::Action;
use crate::actions::context::ActionContext;
use crate::rule::Id;
use std::ops::RangeInclusive;

#[derive(Debug)]
pub struct RuleRemoveById {
    name: String,
    /// The ids, as ranges (of one id for a single one).
    ids: Vec<RangeInclusive<Id>>,
}

impl RuleRemoveById {
    /// The payload is `ruleRemoveById=` followed by space separated ids
    /// and `first-last` ranges.
    pub fn new(name: &str, payload: &str) -> Result<Self, String> {
        let Some((_, list)) = payload.split_once('=') else {
            return Err(format!("{} is not a valid ID or range", payload));
        };
        Ok(RuleRemoveById { name: name.to_string(), ids: crate::rule::id::parse_list(list)? })
    }
}

impl Action for RuleRemoveById {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, cx: &mut ActionContext<'_, '_, '_>) {
        cx.remove_rules_by_id(&self.ids);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::block::test_support::*;
    use crate::actions::ctl::rule_remove_by_tag::RuleRemoveByTag;
    use crate::actions::ctl::rule_remove_target_by_id::RuleRemoveTargetById;
    use crate::actions::ctl::rule_remove_target_by_tag::RuleRemoveTargetByTag;
    use crate::instance::ModSecurity;
    use crate::rule::message::RuleMessage;
    use crate::transaction::Transaction;

    #[test]
    fn invalid_payloads() {
        let by_id = |a: &str| {
            let (name, payload) = crate::actions::action::name_and_payload(a);
            RuleRemoveById::new(name, payload).unwrap_err()
        };
        assert_eq!(by_id("ctl:ruleRemoveById"), "ruleRemoveById is not a valid ID or range");
        assert_eq!(by_id("ctl:ruleRemoveById=a"), "Not a number or range: a");
        assert_eq!(by_id("ctl:ruleRemoveById=x-2"), "Not a number: x");
        assert_eq!(by_id("ctl:ruleRemoveById=1-y"), "Not a number: y");
        assert_eq!(by_id("ctl:ruleRemoveById=5-2"), "Invalid range: 5-2");
        assert_eq!(by_id("ctl:ruleRemoveById="), "Not a number or range: ");
        assert_eq!(RuleRemoveByTag::new("ctl", "ruleRemoveByTag").unwrap_err(), "ruleRemoveByTag is not a valid tag");
        let target_by_id = |a: &str| {
            let (name, payload) = crate::actions::action::name_and_payload(a);
            RuleRemoveTargetById::new(name, payload).unwrap_err()
        };
        assert_eq!(target_by_id("ctl:ruleRemoveTargetById=1"), "1 is not a valid 'ID;VARIABLE'");
        assert_eq!(target_by_id("ctl:ruleRemoveTargetById=a;ARGS"), "Not able to convert 'a' into a number");
        let target_by_tag = |a: &str| {
            let (name, payload) = crate::actions::action::name_and_payload(a);
            RuleRemoveTargetByTag::new(name, payload).unwrap_err()
        };
        assert_eq!(target_by_tag("ctl:ruleRemoveTargetByTag"), "ruleRemoveTargetByTag is not a valid 'TAG;VARIABLE'");
        assert_eq!(target_by_tag("ctl:ruleRemoveTargetByTag=t"), "t is not a valid 'TAG;VARIABLE'");
    }

    #[test]
    fn evaluate() {
        let ms = ModSecurity::new();
        let rules = rules();
        let r = rule(vec![]);
        let mut t = Transaction::new(&ms, &rules, None);
        let mut rm = RuleMessage::new(&r);
        let actions: Vec<Box<dyn Action>> = vec![
            Box::new(RuleRemoveById::new("ctl", "ruleRemoveById=1  '2' 10-20 \"3\"").unwrap()),
            Box::new(RuleRemoveByTag::new("ctl", "ruleRemoveByTag=attack-sqli").unwrap()),
            Box::new(RuleRemoveTargetById::new("ctl", "ruleRemoveTargetById=981260;ARGS:foo").unwrap()),
            Box::new(RuleRemoveTargetByTag::new("ctl", "ruleRemoveTargetByTag=CRS;REQUEST_HEADERS:x").unwrap()),
        ];
        for a in &actions {
            a.evaluate(&mut ActionContext::new(&mut t, &r, &mut rm));
        }
        assert_eq!(t.ctl.rule_remove_by_id, vec![1..=1, 2..=2, 10..=20, 3..=3]);
        assert_eq!(t.ctl.rule_remove_by_tag, vec!["attack-sqli".to_string()]);
        assert_eq!(t.ctl.rule_remove_target_by_id, vec![(981260, "ARGS:foo".to_string())]);
        assert_eq!(t.ctl.rule_remove_target_by_tag, vec![("CRS".to_string(), "REQUEST_HEADERS:x".to_string())]);
    }
}
