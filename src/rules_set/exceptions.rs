//! Rule exceptions configured by `SecRuleRemoveBy*` and
//! `SecRuleUpdate*`.
//!
//! The entries of every table are kept in the order of the
//! configuration.

use std::collections::HashMap;
use std::sync::Arc;

use crate::actions::action::Kind;
use crate::actions::rule_action::RuleAction;
use crate::rule::Id;
use crate::utils::string::{parser_sanitizer, ssplit, stoi};
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

    /// The entries for the rule with id `rule_id`, in order.
    pub fn for_rule(&self, rule_id: Id) -> &[V] {
        self.by_id.get(&rule_id).map_or(&[], Vec::as_slice)
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
    ranges: Vec<(i32, i32)>,
    numbers: Vec<i32>,
}

impl RulesExceptions {
    pub fn new() -> Self {
        Self::default()
    }

    /// `SecRuleUpdateActionById`: adds the run time actions to the rule
    /// `id`, to run before or after the match according to their kind.
    /// Refuses the actions that make a rule what it is (`id`, `phase`,
    /// `chain`, `rev`, ...): a loaded rule cannot be given another.
    pub fn load_update_action_by_id(&mut self, id: Id, actions: Vec<RuleAction>) -> Result<(), String> {
        if let Some(a) = actions.iter().find(|a| a.kind() == Kind::Configuration) {
            return Err(format!("the action `{}' of a rule cannot be updated", a.name()));
        }
        for a in actions {
            match a.kind() {
                Kind::Configuration => {}
                Kind::RunTimeBeforeMatchAttempt => {
                    self.action_pre_update_target_by_id.emplace(id, Arc::new(a));
                }
                Kind::RunTimeOnlyIfMatch => {
                    self.action_pos_update_target_by_id.emplace(id, Arc::new(a));
                }
            }
        }
        Ok(())
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

    /// Parses the argument of `SecRuleRemoveById` (ids and ranges).
    pub fn load(&mut self, a: &str) -> Result<(), String> {
        let mut added = false;
        for r in ssplit(a.as_bytes(), b' ') {
            let b = parser_sanitizer(String::from_utf8_lossy(&r).into_owned());
            if b.is_empty() {
                continue;
            }
            if let Some(dash) = b.find('-') {
                let n1s = &b[..dash];
                let n2s = &b[dash + 1..];
                let Some(n1n) = stoi(n1s.as_bytes()) else {
                    return Err(format!("Not a number: {}", n1s));
                };
                let Some(n2n) = stoi(n2s.as_bytes()) else {
                    return Err(format!("Not a number: {}", n2s));
                };
                // Note: the C++ code compares the strings, not the numbers.
                if n1s > n2s {
                    return Err(format!("Invalid range: {}", b));
                }
                self.add_range(n1n, n2n);
                added = true;
            } else {
                match stoi(b.as_bytes()) {
                    Some(num) => {
                        self.add_number(num);
                        added = true;
                    }
                    None => return Err(format!("Not a number or range: {}", b)),
                }
            }
        }
        if added {
            return Ok(());
        }
        Err(format!("Not a number or range: {}", a))
    }

    pub fn add_number(&mut self, a: i32) {
        self.numbers.push(a);
    }

    pub fn add_range(&mut self, a: i32, b: i32) {
        self.ranges.push((a, b));
    }

    /// Whether `SecRuleRemoveById` removes the rule id `a`.
    pub fn contains(&self, a: i32) -> bool {
        self.numbers.contains(&a) || self.ranges.iter().any(|&(x, y)| x <= a && y >= a)
    }

    /// Adds the exceptions of `from` (of a merged rule set) to these.
    pub fn merge(&mut self, from: &RulesExceptions) {
        for &a in &from.numbers {
            self.add_number(a);
        }
        for &(a, b) in &from.ranges {
            self.add_range(a, b);
        }
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
        m.emplace(Id::new(1), "a");
        m.emplace(Id::new(2), "x");
        m.emplace(Id::new(1), "b");
        assert_eq!(m.for_rule(Id::new(1)), ["a", "b"]);
        assert_eq!(m.for_rule(Id::new(2)), ["x"]);
        assert!(m.for_rule(Id::new(3)).is_empty());
        let mut n = IdMultimap::default();
        n.emplace(Id::new(1), "c");
        n.merge_from(&m);
        assert_eq!(n.for_rule(Id::new(1)), ["c", "a", "b"]);
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
                .for_rule(Id::new(1))
                .iter()
                .filter_map(|a| match &**a {
                    RuleAction::Tag(tag) => Some(tag.string.evaluate_static_string()),
                    _ => None,
                })
                .collect();
            let targets: Vec<&str> =
                ex.variable_update_target_by_id.for_rule(Id::new(1)).iter().map(|v| v.full_name()).collect();
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

    #[test]
    fn load_ids() {
        let mut e = RulesExceptions::new();
        assert!(e.load("1 5-9").is_ok());
        assert!(e.contains(1) && e.contains(7) && !e.contains(10));
        // Faithful to C++: the bounds are compared as strings ("5" > "10").
        assert_eq!(e.load("5-10").unwrap_err(), "Invalid range: 5-10");
        assert_eq!(e.load("x").unwrap_err(), "Not a number or range: x");
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
