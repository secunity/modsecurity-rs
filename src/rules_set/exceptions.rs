//! Rule exceptions configured by `SecRuleRemoveBy*` and
//! `SecRuleUpdate*`.
//!
//! The entries of every table are kept in the order of the
//! configuration.

use std::collections::HashMap;
use std::ops::RangeInclusive;
use std::sync::Arc;

use crate::actions::rule_action::RuleAction;
use crate::rule::Id;
use crate::variables::variable::Variable;

/// What `SecRuleUpdate...ById` directives give to rules: per rule id, in
/// the order of the configuration.
#[derive(Debug)]
pub struct IdMultimap<V> {
    by_id: HashMap<Id, Vec<V>>,
}

impl<V> Default for IdMultimap<V> {
    fn default() -> Self {
        IdMultimap { by_id: HashMap::new() }
    }
}

impl<V: Clone> IdMultimap<V> {
    pub fn emplace(&mut self, id: Id, value: V) {
        self.by_id.entry(id).or_default().push(value);
    }

    /// The entries for the rule with id `rule_id`, in order (none for a
    /// rule without an id).
    pub fn for_rule(&self, rule_id: impl Into<Option<Id>>) -> &[V] {
        rule_id.into().and_then(|id| self.by_id.get(&id)).map_or(&[], Vec::as_slice)
    }

    /// Adds the entries of `from` (a configuration loaded later) after
    /// the ones already here.
    pub fn merge_from(&mut self, from: &IdMultimap<V>) {
        for (&key, values) in &from.by_id {
            self.by_id.entry(key).or_default().extend(values.iter().cloned());
        }
    }
}

#[derive(Debug, Default)]
pub struct RulesExceptions {
    pub variable_update_target_by_tag: Vec<(Arc<String>, Arc<Variable>)>,
    pub variable_update_target_by_msg: Vec<(Arc<String>, Arc<Variable>)>,
    pub variable_update_target_by_id: IdMultimap<Arc<Variable>>,
    pub action_pre_update_target_by_id: IdMultimap<Arc<RuleAction>>,
    pub action_pos_update_target_by_id: IdMultimap<Arc<RuleAction>>,
    pub remove_rule_by_msg: Vec<String>,
    pub remove_rule_by_tag: Vec<String>,
    /// The ids of `SecRuleRemoveById`: ranges, of one id for a single one.
    removed_ids: Vec<RangeInclusive<Id>>,
}

impl RulesExceptions {
    pub fn new() -> Self {
        Self::default()
    }

    /// `SecRuleUpdateActionById`: adds the actions to the rule `id`: the
    /// transformations to run before the operator, the others on a match.
    pub fn load_update_action_by_id(&mut self, id: Id, actions: Vec<RuleAction>) {
        for a in actions {
            if a.is_transformation() {
                self.action_pre_update_target_by_id.emplace(id, Arc::new(a));
            } else {
                self.action_pos_update_target_by_id.emplace(id, Arc::new(a));
            }
        }
    }

    /// `SecRuleRemoveByMsg`: removes the rules whose `msg` is `msg`.
    pub fn load_remove_rule_by_msg(&mut self, msg: &str) {
        self.remove_rule_by_msg.push(msg.to_string());
    }

    /// `SecRuleRemoveByTag`: removes the rules with the `tag` `tag`.
    pub fn load_remove_rule_by_tag(&mut self, tag: &str) {
        self.remove_rule_by_tag.push(tag.to_string());
    }

    /// `SecRuleUpdateTargetByMsg`: changes the targets of the rules whose
    /// `msg` is `msg`.
    pub fn load_update_target_by_msg(&mut self, msg: &str, vars: Vec<Variable>) {
        for v in vars {
            self.variable_update_target_by_msg.push((Arc::new(msg.to_string()), Arc::from(v)));
        }
    }

    /// `SecRuleUpdateTargetByTag`: changes the targets of the rules with
    /// the `tag` `tag`.
    pub fn load_update_target_by_tag(&mut self, tag: &str, vars: Vec<Variable>) {
        for v in vars {
            self.variable_update_target_by_tag.push((Arc::new(tag.to_string()), Arc::from(v)));
        }
    }

    /// `SecRuleUpdateTargetById`: changes the targets of the rule `id`.
    pub fn load_update_target_by_id(&mut self, id: Id, vars: Vec<Variable>) {
        for v in vars {
            self.variable_update_target_by_id.emplace(id, Arc::from(v));
        }
    }

    /// `SecRuleRemoveById`: the ids and ranges of ids (`first-last`) of
    /// `list`, separated by spaces.
    pub fn load(&mut self, list: &str) -> Result<(), String> {
        self.removed_ids.extend(crate::rule::id::parse_list(list)?);
        Ok(())
    }

    /// Whether `SecRuleRemoveById` removes the rule `id`.
    pub fn contains(&self, id: impl Into<Option<Id>>) -> bool {
        id.into().is_some_and(|id| self.removed_ids.iter().any(|range| range.contains(&id)))
    }

    /// Adds the exceptions of `from` (of a merged rule set) to these.
    pub fn merge(&mut self, from: &RulesExceptions) {
        self.removed_ids.extend(from.removed_ids.iter().cloned());
        for p in &from.variable_update_target_by_tag {
            self.variable_update_target_by_tag.push(p.clone());
        }
        for p in &from.variable_update_target_by_msg {
            self.variable_update_target_by_msg.push(p.clone());
        }
        self.variable_update_target_by_id.merge_from(&from.variable_update_target_by_id);
        self.action_pos_update_target_by_id.merge_from(&from.action_pos_update_target_by_id);
        self.action_pre_update_target_by_id.merge_from(&from.action_pre_update_target_by_id);
        self.remove_rule_by_msg.extend(from.remove_rule_by_msg.iter().cloned());
        self.remove_rule_by_tag.extend(from.remove_rule_by_tag.iter().cloned());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_multimap_keeps_the_order() {
        let mut m = IdMultimap::default();
        m.emplace(1, "a");
        m.emplace(2, "x");
        m.emplace(1, "b");
        assert_eq!(m.for_rule(1), ["a", "b"]);
        assert_eq!(m.for_rule(2), ["x"]);
        assert!(m.for_rule(3).is_empty());
        let mut n = IdMultimap::default();
        n.emplace(1, "c");
        n.merge_from(&m);
        assert_eq!(n.for_rule(1), ["c", "a", "b"]);
    }

    /// The actions and targets that `SecRuleUpdate...ById` directives
    /// give a rule are in the order of the configuration, however many
    /// times it was loaded in pieces. (They were in the order of a C++
    /// hash table: reversed by every other merge of rule sets.)
    #[test]
    fn updates_are_in_the_order_of_the_configuration() {
        let rule = "SecRule ARGS \"@rx x\" \"id:1,phase:1,pass\"\n";
        let updates = "SecRuleUpdateActionById 1 \"tag:'first'\"\nSecRuleUpdateActionById 1 \"tag:'second',tag:'third'\"\n\
                       SecRuleUpdateTargetById 1 \"REQUEST_URI\"\nSecRuleUpdateTargetById 1 \"REQUEST_METHOD\"\n";
        let describe = |rules: &crate::RulesSet| {
            let ex = &rules.properties.exceptions;
            let tags: Vec<String> = ex
                .action_pos_update_target_by_id
                .for_rule(1)
                .iter()
                .filter_map(|a| match &**a {
                    RuleAction::Tag(tag) => Some(String::from_utf8_lossy(&tag.string.text()).into_owned()),
                    _ => None,
                })
                .collect();
            let targets: Vec<&str> =
                ex.variable_update_target_by_id.for_rule(1).iter().map(|v| v.full_name()).collect();
            (tags.join(","), targets.join("|"))
        };
        // In one load, in two, and merged into another rule set twice
        // over (as a connector does for nested locations).
        let mut one = crate::RulesSet::new();
        one.load(&format!("{rule}{updates}")).unwrap();
        let mut two = crate::RulesSet::new();
        two.load(rule).unwrap();
        two.load(updates).unwrap();
        let mut outer = crate::RulesSet::new();
        outer.merge(&mut two).unwrap();
        let mut inner = crate::RulesSet::new();
        inner.merge(&mut outer).unwrap();
        for rules in [&one, &two, &outer, &inner] {
            assert_eq!(describe(rules), ("first,second,third".to_string(), "REQUEST_URI|REQUEST_METHOD".to_string()));
        }
    }

    /// `SecRuleRemoveById` takes ids as rules have them, and compares
    /// the bounds of a range as numbers. (C++ compared the bounds as
    /// text, so `5-10` was refused and `10-5` accepted; read each id as
    /// far as its digits go; and kept ids as 32 bit integers, so that
    /// removing rule 1 also removed rule 4294967297.)
    #[test]
    fn load_ids() {
        let id = |n: Id| n;
        let mut e = RulesExceptions::new();
        assert!(e.load("1 5-9").is_ok());
        assert!(e.contains(id(1)) && e.contains(id(5)) && e.contains(id(9)));
        assert!(!e.contains(id(2)) && !e.contains(id(10)) && !e.contains(id(4294967297)));
        assert!(e.load("5-10 4294967297 \"20\"").is_ok());
        assert!(e.contains(id(10)) && e.contains(id(4294967297)) && e.contains(id(20)));
        for (list, error) in [
            ("10-5", "Invalid range: 10-5"),
            ("x", "Not a number or range: x"),
            ("12abc", "Not a number or range: 12abc"),
            ("1-x", "Not a number: x"),
            ("-5", "Not a number: "),
            ("", "Not a number or range: "),
            ("  ", "Not a number or range:   "),
        ] {
            assert_eq!(e.load(list).unwrap_err(), error, "{list:?}");
        }
        // A list with an error adds nothing.
        assert!(e.load("30 x").is_err() && !e.contains(id(30)));
    }

    /// `SecRuleUpdateActionById` cannot give a rule another id, phase or
    /// chain. (C++ prints "General failure" on standard output and goes
    /// on without the action.)
    #[test]
    fn update_action_by_id_refuses_what_makes_the_rule() {
        let load = |actions: &str| {
            let mut rules = crate::RulesSet::new();
            rules.load(&format!(
                "SecRule ARGS \"@rx x\" \"id:1,phase:1,pass\"\nSecRuleUpdateActionById 1 \"{actions}\"\n"
            ))
        };
        assert!(load("deny,status:403,tag:'x',t:lowercase").is_ok());
        for actions in ["id:2", "pass,phase:2", "chain", "rev:'2'", "ver:'x'", "maturity:1", "accuracy:1"] {
            let error = load(actions).unwrap_err().to_string();
            assert!(error.contains("SecRuleUpdateActionById: the action `"), "{actions}: {error}");
        }
    }
}
