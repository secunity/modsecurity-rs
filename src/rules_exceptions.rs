//! Port of `headers/modsecurity/rules_exceptions.h` and
//! `src/rules_exceptions.cc`.
//!
//! The C++ class keeps the "update target/action by id" tables in
//! `std::unordered_multimap<double, ...>`. Every consumer looks those
//! tables up by rule id, so the only observable property of the container
//! is the relative order of entries sharing an id: libstdc++ inserts a new
//! element in front of its equivalents. [`IdMultimap`] reproduces exactly
//! that. The tag/msg tables are keyed by freshly allocated
//! `shared_ptr<std::string>` (every entry is a distinct key, ordered by
//! pointer hash); they are kept in insertion order here.

use std::collections::HashMap;
use std::sync::Arc;

use crate::actions::action::{Action, Kind};
use crate::utils::string::{parser_sanitizer, ssplit, stoi};
use crate::variables::variable::Variable;

/// Multimap keyed by rule id where a new entry goes in front of the existing
/// entries with the same id (libstdc++ `unordered_multimap::emplace`).
///
/// The ids of the entries are C++ `double`s (`SecRuleUpdateTargetById 1.5e3`
/// is accepted), and that is deliberately kept: the key is the bit pattern
/// of the `f64` (with `-0.0` folded into `0.0`), which gives the same
/// equality as comparing the numbers (ids are never NaN). Lookups take the
/// integer id of a rule.
#[derive(Debug)]
pub struct IdMultimap<V> {
    by_id: HashMap<u64, Vec<V>>,
}

impl<V> Default for IdMultimap<V> {
    fn default() -> Self {
        IdMultimap { by_id: HashMap::new() }
    }
}

fn id_key(id: f64) -> u64 {
    if id == 0.0 { 0.0f64.to_bits() } else { id.to_bits() }
}

impl<V: Clone> IdMultimap<V> {
    pub fn emplace(&mut self, id: f64, value: V) {
        self.by_id.entry(id_key(id)).or_default().insert(0, value);
    }

    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    /// The entries for the rule with id `rule_id`, in container order. An
    /// entry applies when its id (a `double`, as parsed by `std::stod`)
    /// equals the rule id converted to `double`, as in C++.
    pub fn for_rule(&self, rule_id: i64) -> &[V] {
        self.by_id.get(&id_key(rule_id as f64)).map_or(&[], Vec::as_slice)
    }

    /// Emplaces the entries of `from`, walking each id's entries in
    /// container order (so a merge reverses them, as with libstdc++).
    pub fn merge_from(&mut self, from: &IdMultimap<V>) {
        for (&key, values) in &from.by_id {
            let to = self.by_id.entry(key).or_default();
            for v in values {
                to.insert(0, v.clone());
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct RulesExceptions {
    pub variable_update_target_by_tag: Vec<(Arc<String>, Arc<Variable>)>,
    pub variable_update_target_by_msg: Vec<(Arc<String>, Arc<Variable>)>,
    pub variable_update_target_by_id: IdMultimap<Arc<Variable>>,
    pub action_pre_update_target_by_id: IdMultimap<Arc<dyn Action>>,
    pub action_pos_update_target_by_id: IdMultimap<Arc<dyn Action>>,
    pub remove_rule_by_msg: Vec<String>,
    pub remove_rule_by_tag: Vec<String>,
    ranges: Vec<(i32, i32)>,
    numbers: Vec<i32>,
}

impl RulesExceptions {
    pub fn new() -> Self {
        Self::default()
    }

    /// `loadUpdateActionById`
    pub fn load_update_action_by_id(&mut self, id: f64, actions: Vec<Box<dyn Action>>) {
        for a in actions {
            match a.kind() {
                Kind::Configuration => {
                    println!(
                        "General failure, action: {} has not expected to be used with UpdateActionByID.",
                        a.name()
                    );
                }
                Kind::RunTimeBeforeMatchAttempt => {
                    self.action_pre_update_target_by_id.emplace(id, Arc::from(a));
                }
                Kind::RunTimeOnlyIfMatch => {
                    self.action_pos_update_target_by_id.emplace(id, Arc::from(a));
                }
            }
        }
    }

    /// `loadRemoveRuleByMsg`
    pub fn load_remove_rule_by_msg(&mut self, msg: &str) {
        self.remove_rule_by_msg.push(msg.to_string());
    }

    /// `loadRemoveRuleByTag`
    pub fn load_remove_rule_by_tag(&mut self, tag: &str) {
        self.remove_rule_by_tag.push(tag.to_string());
    }

    /// `loadUpdateTargetByMsg`
    pub fn load_update_target_by_msg(&mut self, msg: &str, vars: Vec<Variable>) {
        for v in vars {
            self.variable_update_target_by_msg.push((Arc::new(msg.to_string()), Arc::from(v)));
        }
    }

    /// `loadUpdateTargetByTag`
    pub fn load_update_target_by_tag(&mut self, tag: &str, vars: Vec<Variable>) {
        for v in vars {
            self.variable_update_target_by_tag.push((Arc::new(tag.to_string()), Arc::from(v)));
        }
    }

    /// `loadUpdateTargetById`
    pub fn load_update_target_by_id(&mut self, id: f64, vars: Vec<Variable>) {
        for v in vars {
            self.variable_update_target_by_id.emplace(id, Arc::from(v));
        }
    }

    /// `load`: parses the argument of `SecRuleRemoveById` (ids and ranges).
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
                self.add_range(n1n as i32, n2n as i32);
                added = true;
            } else {
                match stoi(b.as_bytes()) {
                    Some(num) => {
                        self.add_number(num as i32);
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

    /// `contains`
    pub fn contains(&self, a: i32) -> bool {
        self.numbers.contains(&a) || self.ranges.iter().any(|&(x, y)| x <= a && y >= a)
    }

    /// `merge`
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
    fn id_multimap_front_insertion() {
        let mut m = IdMultimap::default();
        m.emplace(1.0, "a");
        m.emplace(2.0, "x");
        m.emplace(1.0, "b");
        assert_eq!(m.for_rule(1), ["b", "a"]);
        assert_eq!(m.for_rule(2), ["x"]);
        assert!(m.for_rule(3).is_empty());
        let mut n = IdMultimap::default();
        n.emplace(1.0, "c");
        n.merge_from(&m);
        // A merge walks the entries in container order, emplacing each in
        // front: it reverses them (as with libstdc++).
        assert_eq!(n.for_rule(1), ["a", "b", "c"]);
        // -0.0 and 0.0 are the same id.
        m.emplace(-0.0, "z");
        assert_eq!(m.for_rule(0), ["z"]);
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
}
