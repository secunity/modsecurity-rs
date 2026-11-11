//! Port of `headers/modsecurity/rules_exceptions.h` and
//! `src/rules_exceptions.cc`.
//!
//! The C++ class keeps the "update target/action by id" tables in
//! `std::unordered_multimap<double, ...>`. Every consumer filters those
//! tables by rule id, so the only observable property of the container is
//! the relative order of entries sharing an id: libstdc++ inserts a new
//! element in front of its equivalents. [`IdMultimap`] reproduces exactly
//! that. The tag/msg tables are keyed by freshly allocated
//! `shared_ptr<std::string>` (every entry is a distinct key, ordered by
//! pointer hash); they are kept in insertion order here.

use std::sync::Arc;

use crate::actions::action::{Action, Kind};
use crate::utils::string::{parser_sanitizer, ssplit, stoi};
use crate::variables::variable::Variable;

/// Multimap keyed by rule id where a new entry goes in front of the existing
/// entries with the same id (libstdc++ `unordered_multimap::emplace`).
#[derive(Debug)]
pub struct IdMultimap<V> {
    entries: Vec<(f64, V)>,
}

impl<V> Default for IdMultimap<V> {
    fn default() -> Self {
        IdMultimap { entries: Vec::new() }
    }
}

impl<V: Clone> IdMultimap<V> {
    pub fn emplace(&mut self, key: f64, value: V) {
        match self.entries.iter().position(|(k, _)| *k == key) {
            Some(p) => self.entries.insert(p, (key, value)),
            None => self.entries.push((key, value)),
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &(f64, V)> {
        self.entries.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The entries for one rule id, in container order.
    pub fn for_id(&self, id: f64) -> impl Iterator<Item = &V> {
        self.entries.iter().filter(move |(k, _)| *k == id).map(|(_, v)| v)
    }
}

#[derive(Debug, Default)]
pub struct RulesExceptions {
    pub variable_update_target_by_tag: Vec<(Arc<String>, Arc<dyn Variable>)>,
    pub variable_update_target_by_msg: Vec<(Arc<String>, Arc<dyn Variable>)>,
    pub variable_update_target_by_id: IdMultimap<Arc<dyn Variable>>,
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
    pub fn load_update_action_by_id(&mut self, id: f64, actions: Vec<Box<dyn Action>>) -> Result<(), String> {
        for a in actions {
            match a.action_kind() {
                Kind::ConfigurationKind => {
                    println!(
                        "General failure, action: {} has not expected to be used with UpdateActionByID.",
                        a.name()
                    );
                }
                Kind::RunTimeBeforeMatchAttemptKind => {
                    self.action_pre_update_target_by_id.emplace(id, Arc::from(a));
                }
                Kind::RunTimeOnlyIfMatchKind => {
                    self.action_pos_update_target_by_id.emplace(id, Arc::from(a));
                }
            }
        }
        Ok(())
    }

    /// `loadRemoveRuleByMsg`
    pub fn load_remove_rule_by_msg(&mut self, msg: &str) -> Result<(), String> {
        self.remove_rule_by_msg.push(msg.to_string());
        Ok(())
    }

    /// `loadRemoveRuleByTag`
    pub fn load_remove_rule_by_tag(&mut self, tag: &str) -> Result<(), String> {
        self.remove_rule_by_tag.push(tag.to_string());
        Ok(())
    }

    /// `loadUpdateTargetByMsg`
    pub fn load_update_target_by_msg(&mut self, msg: &str, vars: Vec<Box<dyn Variable>>) -> Result<(), String> {
        for v in vars {
            self.variable_update_target_by_msg.push((Arc::new(msg.to_string()), Arc::from(v)));
        }
        Ok(())
    }

    /// `loadUpdateTargetByTag`
    pub fn load_update_target_by_tag(&mut self, tag: &str, vars: Vec<Box<dyn Variable>>) -> Result<(), String> {
        for v in vars {
            self.variable_update_target_by_tag.push((Arc::new(tag.to_string()), Arc::from(v)));
        }
        Ok(())
    }

    /// `loadUpdateTargetById`
    pub fn load_update_target_by_id(&mut self, id: f64, vars: Vec<Box<dyn Variable>>) -> Result<(), String> {
        for v in vars {
            self.variable_update_target_by_id.emplace(id, Arc::from(v));
        }
        Ok(())
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

    pub fn add_number(&mut self, a: i32) -> bool {
        self.numbers.push(a);
        true
    }

    pub fn add_range(&mut self, a: i32, b: i32) -> bool {
        self.ranges.push((a, b));
        true
    }

    /// `contains`
    pub fn contains(&self, a: i32) -> bool {
        self.numbers.contains(&a) || self.ranges.iter().any(|&(x, y)| x <= a && y >= a)
    }

    /// `merge`
    pub fn merge(&mut self, from: &RulesExceptions) -> bool {
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
        for (k, v) in from.variable_update_target_by_id.iter() {
            self.variable_update_target_by_id.emplace(*k, v.clone());
        }
        for (k, v) in from.action_pos_update_target_by_id.iter() {
            self.action_pos_update_target_by_id.emplace(*k, v.clone());
        }
        for (k, v) in from.action_pre_update_target_by_id.iter() {
            self.action_pre_update_target_by_id.emplace(*k, v.clone());
        }
        self.remove_rule_by_msg.extend(from.remove_rule_by_msg.iter().cloned());
        self.remove_rule_by_tag.extend(from.remove_rule_by_tag.iter().cloned());
        true
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
        assert_eq!(m.for_id(1.0).copied().collect::<Vec<_>>(), vec!["b", "a"]);
        let mut n = IdMultimap::default();
        for (k, v) in m.iter() {
            n.emplace(*k, *v);
        }
        // One merge restores insertion order, as with libstdc++.
        assert_eq!(n.for_id(1.0).copied().collect::<Vec<_>>(), vec!["a", "b"]);
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
