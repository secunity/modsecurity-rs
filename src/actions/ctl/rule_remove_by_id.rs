//! Port of `src/actions/ctl/rule_remove_by_id.cc`, `src/actions/ctl/rule_remove_by_id.h`.
//!
//! `ctl:ruleRemoveById=1 2 100-200` — disables rules (by id or id range)
//! for the rest of the transaction.

use crate::actions::action::{Action, name_and_payload};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;
use crate::utils::string::{parser_sanitizer, ssplit, stoi};

#[derive(Debug)]
pub struct RuleRemoveById {
    name: String,
    ranges: Vec<(i32, i32)>,
    ids: Vec<i32>,
}

/// `std::stoi` (no digits or out of `int` range -> `None`).
fn stoi_int(s: &str) -> Option<i32> {
    stoi(s.as_bytes()).and_then(|v| i32::try_from(v).ok())
}

impl RuleRemoveById {
    /// The payload is `ruleRemoveById=` followed by space separated ids
    /// and `first-last` ranges.
    pub fn new(action: &str) -> Result<Self, String> {
        let (name, payload) = name_and_payload(action);
        let mut ranges = Vec::new();
        let mut ids = Vec::new();
        let Some((_, what)) = payload.split_once('=') else {
            return Err(format!("{} is not a valid ID or range", payload));
        };
        let mut added = false;

        for a in ssplit(what.as_bytes(), b' ') {
            let b = parser_sanitizer(String::from_utf8_lossy(&a).into_owned());
            if b.is_empty() {
                continue;
            }

            if let Some(dash) = b.find('-') {
                let n1s = &b[..dash];
                let n2s = &b[dash + 1..];
                let Some(n1n) = stoi_int(n1s) else {
                    return Err(format!("Not a number: {}", n1s));
                };
                let Some(n2n) = stoi_int(n2s) else {
                    return Err(format!("Not a number: {}", n2s));
                };
                if n1n > n2n {
                    return Err(format!("Invalid range: {}", b));
                }
                ranges.push((n1n, n2n));
                added = true;
            } else {
                let Some(num) = stoi_int(&b) else {
                    return Err(format!("Not a number or range: {}", b));
                };
                ids.push(num);
                added = true;
            }
        }

        if !added {
            return Err(format!("Not a number or range: {}", what));
        }
        Ok(RuleRemoveById { name: name.to_string(), ranges, ids })
    }
}

impl Action for RuleRemoveById {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, _rm: &mut RuleMessage<'_>) {
        t.rule_remove_by_id.extend_from_slice(&self.ids);
        t.rule_remove_by_id_range.extend_from_slice(&self.ranges);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::block::test_support::*;
    use crate::actions::ctl::rule_remove_by_tag::RuleRemoveByTag;
    use crate::actions::ctl::rule_remove_target_by_id::RuleRemoveTargetById;
    use crate::actions::ctl::rule_remove_target_by_tag::RuleRemoveTargetByTag;
    use crate::modsecurity::ModSecurity;

    #[test]
    fn invalid_payloads() {
        let by_id = |a: &str| RuleRemoveById::new(a).unwrap_err();
        assert_eq!(by_id("ctl:ruleRemoveById"), "ruleRemoveById is not a valid ID or range");
        assert_eq!(by_id("ctl:ruleRemoveById=a"), "Not a number or range: a");
        assert_eq!(by_id("ctl:ruleRemoveById=x-2"), "Not a number: x");
        assert_eq!(by_id("ctl:ruleRemoveById=1-y"), "Not a number: y");
        assert_eq!(by_id("ctl:ruleRemoveById=5-2"), "Invalid range: 5-2");
        assert_eq!(by_id("ctl:ruleRemoveById="), "Not a number or range: ");
        assert_eq!(RuleRemoveByTag::new("ctl:ruleRemoveByTag").unwrap_err(), "ruleRemoveByTag is not a valid tag");
        let target_by_id = |a: &str| RuleRemoveTargetById::new(a).unwrap_err();
        assert_eq!(target_by_id("ctl:ruleRemoveTargetById=1"), "1 is not a valid 'ID;VARIABLE'");
        assert_eq!(target_by_id("ctl:ruleRemoveTargetById=a;ARGS"), "Not able to convert 'a' into a number");
        let target_by_tag = |a: &str| RuleRemoveTargetByTag::new(a).unwrap_err();
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
            Box::new(RuleRemoveById::new("ctl:ruleRemoveById=1  '2' 10-20 \"3\"").unwrap()),
            Box::new(RuleRemoveByTag::new("ctl:ruleRemoveByTag=attack-sqli").unwrap()),
            Box::new(RuleRemoveTargetById::new("ctl:ruleRemoveTargetById=981260;ARGS:foo").unwrap()),
            Box::new(RuleRemoveTargetByTag::new("ctl:ruleRemoveTargetByTag=CRS;REQUEST_HEADERS:x").unwrap()),
        ];
        for a in &actions {
            a.evaluate(&r, &mut t, &mut rm);
        }
        assert_eq!(t.rule_remove_by_id, vec![1, 2, 3]);
        assert_eq!(t.rule_remove_by_id_range, vec![(10, 20)]);
        assert_eq!(t.rule_remove_by_tag, vec!["attack-sqli".to_string()]);
        assert_eq!(t.rule_remove_target_by_id, vec![(981260, "ARGS:foo".to_string())]);
        assert_eq!(t.rule_remove_target_by_tag, vec![("CRS".to_string(), "REQUEST_HEADERS:x".to_string())]);
    }
}
