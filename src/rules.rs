//! Port of `headers/modsecurity/rules.h`: the rules of one phase.
//!
//! Rules are shared (`std::shared_ptr` in C++, `Arc` here) because merging
//! rule sets (`RulesSet::merge`) copies them into other sets.

use std::sync::Arc;

use crate::rule::Rule;

#[derive(Debug, Default, Clone)]
pub struct Rules {
    pub rules: Vec<Arc<Rule>>,
}

impl Rules {
    pub fn dump(&self) {
        for r in &self.rules {
            println!("    Rule ID: {}--{:p}", r.get_reference(), Arc::as_ptr(r));
        }
    }

    /// `append(from, ids, err)`: fails if a `SecRule` id of `from` is in
    /// the sorted `ids` list; returns the number of rules of `from`.
    pub fn append(&mut self, from: &Rules, ids: &[i64], err: &mut String) -> i32 {
        for r in &from.rules {
            if let Some(id) = r.rule_with_operator_id()
                && ids.binary_search(&id).is_ok()
            {
                err.push_str(&format!("Rule id: {} is duplicated\n", id));
                return -1;
            }
        }
        self.rules.extend(from.rules.iter().cloned());
        from.rules.len() as i32
    }

    /// `insert(rule)`
    pub fn insert(&mut self, rule: Arc<Rule>) -> bool {
        self.insert_checked(rule, None, None)
    }

    /// `insert(rule, ids, err)`
    pub fn insert_checked(&mut self, rule: Arc<Rule>, ids: Option<&[i64]>, err: Option<&mut String>) -> bool {
        if let (Some(id), Some(ids)) = (rule.rule_with_operator_id(), ids)
            && ids.binary_search(&id).is_ok()
        {
            if let Some(err) = err {
                err.push_str(&format!("Rule id: {} is duplicated\n", id));
            }
            return false;
        }
        self.rules.push(rule);
        true
    }

    pub fn size(&self) -> usize {
        self.rules.len()
    }

    pub fn at(&self, index: usize) -> &Arc<Rule> {
        &self.rules[index]
    }
}
