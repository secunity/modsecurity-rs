//! Phase-indexed rule storage and ordered rule-set merging.

use std::sync::Arc;

use crate::modsecurity::{NUMBER_OF_PHASES, Phases};
use crate::rule::Rule;

#[derive(Debug, Default, Clone)]
pub struct RulesSetPhases {
    /// One list per phase, plus an eighth that C++ has and `dump` prints.
    rules_at_phase: [Vec<Arc<Rule>>; NUMBER_OF_PHASES + 1],
}

impl RulesSetPhases {
    /// `insert`: adds the rule to its phase. Returns whether it has one.
    pub fn insert(&mut self, rule: Arc<Rule>) -> bool {
        let Some(phase) = rule.phase() else {
            return false;
        };
        self.rules_at_phase[phase.index()].push(rule);
        true
    }

    /// `append`: merges `from` into `self` phase by phase, refusing
    /// duplicated `SecRule` ids. Returns the number of appended rules. On a
    /// duplicate the phases before it stay appended (as in C++).
    pub fn append(&mut self, from: &RulesSetPhases) -> Result<usize, String> {
        let mut ids: Vec<i64> =
            self.rules_at_phase.iter().flatten().filter_map(|r| r.rule_with_operator_id()).collect();
        ids.sort();
        let mut amount_of_rules = 0;
        for (to, from) in self.rules_at_phase.iter_mut().zip(&from.rules_at_phase) {
            // Check the entire phase before appending any of it. Keep the
            // original destination ids throughout the merge: source ids are
            // not added to this list as earlier phases are appended.
            if let Some(id) =
                from.iter().filter_map(|r| r.rule_with_operator_id()).find(|id| ids.binary_search(id).is_ok())
            {
                return Err(format!("Rule id: {} is duplicated\n", id));
            }
            to.extend(from.iter().cloned());
            amount_of_rules += from.len();
        }
        Ok(amount_of_rules)
    }

    pub fn dump(&self) {
        // The C++ loop runs to `<= NUMBER_OF_PHASES` (index 7 exists).
        for (i, rules) in self.rules_at_phase.iter().enumerate() {
            println!("Phase: {} ({} rules)", i, rules.len());
            for rule in rules {
                println!("    Rule ID: {}--{:p}", rule.reference(), Arc::as_ptr(rule));
            }
        }
    }

    pub fn for_phase(&self, phase: Phases) -> &[Arc<Rule>] {
        &self.rules_at_phase[phase.index()]
    }

    pub fn for_phase_mut(&mut self, phase: Phases) -> &mut [Arc<Rule>] {
        &mut self.rules_at_phase[phase.index()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::driver::Driver;

    fn parse(text: &str) -> RulesSetPhases {
        let mut driver = Driver::new();
        assert!(driver.parse(text, "merge-test"), "{}", driver.properties.parser_error);
        driver.rules_set_phases
    }

    fn ids(phases: &RulesSetPhases, phase: Phases) -> Vec<i64> {
        phases.for_phase(phase).iter().filter_map(|r| r.rule_with_operator_id()).collect()
    }

    #[test]
    fn merge_failure_keeps_only_complete_earlier_phases() {
        let mut to = parse(r#"SecRule ARGS "@rx x" "id:2,phase:2,pass""#);
        let from = parse(
            r#"
            SecRule ARGS "@rx x" "id:1,phase:1,pass"
            SecRule ARGS "@rx x" "id:3,phase:2,pass"
            SecRule ARGS "@rx x" "id:2,phase:2,pass"
            SecRule ARGS "@rx x" "id:4,phase:3,pass"
        "#,
        );
        assert_eq!(to.append(&from), Err("Rule id: 2 is duplicated\n".into()));
        assert_eq!(ids(&to, Phases::RequestHeaders), [1]);
        assert_eq!(ids(&to, Phases::RequestBody), [2]);
        assert!(ids(&to, Phases::ResponseHeaders).is_empty());
        assert_eq!(ids(&from, Phases::RequestBody), [3, 2]);
        assert!(Arc::ptr_eq(&to.for_phase(Phases::RequestHeaders)[0], &from.for_phase(Phases::RequestHeaders)[0]));
    }

    #[test]
    fn merge_appends_in_order_and_only_checks_operator_rule_ids() {
        let mut to = parse(r#"SecRule ARGS "@rx x" "id:1,phase:1,pass""#);
        let from = parse(
            r#"
            SecAction "id:1,phase:1,pass"
            SecRule ARGS "@rx x" "id:2,phase:1,pass"
            SecRule ARGS "@rx x" "id:3,phase:1,pass"
        "#,
        );
        assert_eq!(to.append(&from), Ok(3));
        assert_eq!(ids(&to, Phases::RequestHeaders), [1, 2, 3]);
        for (appended, original) in
            to.for_phase(Phases::RequestHeaders)[1..].iter().zip(from.for_phase(Phases::RequestHeaders))
        {
            assert!(Arc::ptr_eq(appended, original));
        }
    }
}
