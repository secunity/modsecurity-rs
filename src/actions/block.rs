//! `block`: does what the `SecDefaultAction` of the rule's phase says to
//! do with a request (`deny`, `pass`, ...). What that is belongs to the
//! rule set, so the action has no behavior of its own: the rule runs the
//! `block_actions` of its plan (`Rule::execute_action`).

use crate::actions::action::Action;

#[derive(Debug)]
pub struct Block {
    name: String,
}

impl Block {
    pub fn new(name: &str) -> Self {
        Block { name: name.to_string() }
    }
}

impl Action for Block {
    fn name(&self) -> &str {
        &self.name
    }
}

/// Shared helpers for the unit tests of the actions: a rule set whose debug
/// log is captured in memory, rule construction, and a `TX:` variable with
/// the dynamic-element hooks used by `setvar`.
#[cfg(test)]
pub(crate) mod test_support {
    pub use crate::actions::rule_action::RuleAction;
    use crate::debug_log::test_support::CaptureLog;
    use crate::rule::{Rule, RuleKind};
    use crate::rules_set::RulesSet;
    use crate::run_time_string::RunTimeString;
    use crate::transaction::Transaction;
    use crate::variables::variable::Variable;
    use crate::variables::{VariableSelector, new_variable};

    pub fn rules() -> RulesSet {
        RulesSet::with_debug_log(Box::new(CaptureLog::default()))
    }

    /// The debug messages logged so far.
    pub fn logs(t: &Transaction<'_>) -> Vec<String> {
        CaptureLog::lines_of(t.rules.properties.debug_log.as_ref())
    }

    pub fn has_log(t: &Transaction<'_>, msg: &str) -> bool {
        logs(t).iter().any(|l| l == msg)
    }

    /// A `SecAction` with these actions (configuration actions applied).
    pub fn rule(actions: Vec<RuleAction>) -> Rule {
        Rule::new(Some(actions), None, "test.conf", 1, RuleKind::SecAction)
    }

    pub fn rts(s: &str) -> RunTimeString {
        RunTimeString::from_text(s)
    }

    /// `TX:<name>` as a `setvar` target (the key is a macro string).
    pub fn tx(name: &str) -> Variable {
        new_variable("TX", VariableSelector::Dynamic(rts(name))).expect("TX is a variable")
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use crate::instance::ModSecurity;
    use crate::transaction::Transaction;

    /// `block` runs the disruptive action of the phase's
    /// `SecDefaultAction`, and nothing else of it.
    #[test]
    fn block_runs_default_disruptive_actions() {
        let run = |conf: &str| {
            let ms = ModSecurity::new();
            let mut rules = rules();
            rules.load(&format!("SecRuleEngine On\n{conf}")).unwrap();
            let mut t = Transaction::new(&ms, &rules, None);
            t.process_uri(b"/", b"GET", b"1.1");
            t.process_request_headers();
            (t.outcome.intervention.status, has_log(&t, "Marking request as disruptive."), logs(&t))
        };

        let (status, marked, logs) =
            run("SecDefaultAction \"phase:1,log,deny,status:403\"\nSecAction \"id:1,phase:1,block\"");
        assert!(marked, "{logs:?}");
        assert_eq!(status, 403);

        // Nothing happens in a phase without default actions.
        let (status, marked, _) = run("SecAction \"id:1,phase:1,block\"");
        assert!(marked);
        assert_eq!(status, 200);
    }

    /// `block` is a disruptive action however it is written: it does not
    /// run when the rule engine only detects. (`BLOCK` used to, as in
    /// C++: the action was recognised by its name in lower case.)
    #[test]
    fn block_in_capitals_is_still_disruptive() {
        let denied = |engine: &str, block: &str| {
            let ms = ModSecurity::new();
            let mut rules = rules();
            rules
                .load(&format!(
                    "SecRuleEngine {engine}\nSecDefaultAction \"phase:1,log,deny,status:403\"\n\
                     SecAction \"id:1,phase:1,{block}\""
                ))
                .unwrap();
            let mut t = Transaction::new(&ms, &rules, None);
            t.process_uri(b"/", b"GET", b"1.1");
            t.process_request_headers();
            t.intervention().is_some()
        };
        for block in ["block", "BLOCK", "Block"] {
            assert!(denied("On", block), "{block}");
            assert!(!denied("DetectionOnly", block), "{block}");
        }
    }
}
