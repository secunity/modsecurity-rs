//! Port of `headers/modsecurity/rules_set_phases.h` and
//! `src/rules_set_phases.cc`.

use std::sync::Arc;

use crate::modsecurity::NUMBER_OF_PHASES;
use crate::rule::Rule;
use crate::rules::Rules;

#[derive(Debug, Default, Clone)]
pub struct RulesSetPhases {
    rules_at_phase: [Rules; 8],
}

impl RulesSetPhases {
    /// `insert`
    pub fn insert(&mut self, rule: Arc<Rule>) -> bool {
        let phase = rule.get_phase();
        if phase < 0 || phase as usize >= NUMBER_OF_PHASES {
            return false;
        }
        self.rules_at_phase[phase as usize].insert(rule);
        true
    }

    /// `append`: merges `from` into `self`, refusing duplicated `SecRule`
    /// ids. Returns the number of appended rules or -1.
    pub fn append(&mut self, from: &RulesSetPhases, err: &mut String) -> i32 {
        let mut amount_of_rules = 0;
        let mut v: Vec<i64> = Vec::new();
        for i in 0..NUMBER_OF_PHASES {
            for r in &self.rules_at_phase[i].rules {
                if let Some(id) = r.rule_with_operator_id() {
                    v.push(id);
                }
            }
        }
        v.sort();
        for phase in 0..NUMBER_OF_PHASES {
            let res = self.rules_at_phase[phase].append(&from.rules_at_phase[phase], &v, err);
            if res < 0 {
                return res;
            }
            amount_of_rules += res;
        }
        amount_of_rules
    }

    pub fn dump(&self) {
        // The C++ loop runs to `<= NUMBER_OF_PHASES` (index 7 exists).
        for i in 0..=NUMBER_OF_PHASES {
            println!("Phase: {} ({} rules)", i, self.rules_at_phase[i].size());
            self.rules_at_phase[i].dump();
        }
    }

    pub fn at(&self, index: usize) -> &Rules {
        &self.rules_at_phase[index]
    }

    pub fn at_mut(&mut self, index: usize) -> &mut Rules {
        &mut self.rules_at_phase[index]
    }
}
