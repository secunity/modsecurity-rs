//! Port of `headers/modsecurity/rules_set_phases.h` and
//! `src/rules_set_phases.cc`.

use std::sync::Arc;

use crate::modsecurity::{NUMBER_OF_PHASES, Phases};
use crate::rule::Rule;
use crate::rules::Rules;

#[derive(Debug, Default, Clone)]
pub struct RulesSetPhases {
    /// One list per phase, plus an eighth that C++ has and `dump` prints.
    rules_at_phase: [Rules; 8],
}

impl RulesSetPhases {
    /// `insert`: adds the rule to its phase. Returns whether it has one.
    pub fn insert(&mut self, rule: Arc<Rule>) -> bool {
        let Some(phase) = rule.phase() else {
            return false;
        };
        self.rules_at_phase[phase.index()].insert(rule);
        true
    }

    /// `append`: merges `from` into `self` phase by phase, refusing
    /// duplicated `SecRule` ids. Returns the number of appended rules. On a
    /// duplicate the phases before it stay appended (as in C++).
    pub fn append(&mut self, from: &RulesSetPhases) -> Result<usize, String> {
        let mut ids: Vec<i64> =
            self.rules_at_phase.iter().flat_map(|p| &p.rules).filter_map(|r| r.rule_with_operator_id()).collect();
        ids.sort();
        let mut amount_of_rules = 0;
        for (to, from) in self.rules_at_phase.iter_mut().zip(&from.rules_at_phase) {
            amount_of_rules += to.append(from, &ids)?;
        }
        Ok(amount_of_rules)
    }

    pub fn dump(&self) {
        // The C++ loop runs to `<= NUMBER_OF_PHASES` (index 7 exists).
        for i in 0..=NUMBER_OF_PHASES {
            println!("Phase: {} ({} rules)", i, self.rules_at_phase[i].size());
            self.rules_at_phase[i].dump();
        }
    }

    pub fn at(&self, phase: Phases) -> &Rules {
        &self.rules_at_phase[phase.index()]
    }

    pub fn at_mut(&mut self, phase: Phases) -> &mut Rules {
        &mut self.rules_at_phase[phase.index()]
    }
}
