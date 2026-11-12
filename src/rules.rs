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
            println!("    Rule ID: {}--{:p}", r.reference(), Arc::as_ptr(r));
        }
    }

    /// `append(from, ids, err)`: appends the rules of `from`, unless one of
    /// its `SecRule` ids is in the sorted `ids` list. Returns the number of
    /// rules appended.
    pub fn append(&mut self, from: &Rules, ids: &[i64]) -> Result<usize, String> {
        if let Some(id) =
            from.rules.iter().filter_map(|r| r.rule_with_operator_id()).find(|id| ids.binary_search(id).is_ok())
        {
            return Err(format!("Rule id: {} is duplicated\n", id));
        }
        self.rules.extend(from.rules.iter().cloned());
        Ok(from.rules.len())
    }

    /// `insert(rule)`
    pub fn insert(&mut self, rule: Arc<Rule>) {
        self.rules.push(rule);
    }

    pub fn size(&self) -> usize {
        self.rules.len()
    }

    pub fn at(&self, index: usize) -> &Arc<Rule> {
        &self.rules[index]
    }
}
