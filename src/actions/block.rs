//! Port of `src/actions/block.cc`, `src/actions/block.h`.
//!
//! `block` — executes the disruptive actions of the `SecDefaultAction` of
//! the rule's phase. Rules containing it are classified by
//! `RuleWithActions` (it is kept with the run time actions and flags the
//! rule as containing a static block action).

use crate::actions::action::{Action, name_of};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct Block {
    name: String,
}

impl Block {
    pub fn new(action: &str) -> Self {
        Block { name: name_of(action) }
    }
}

impl Action for Block {
    fn name(&self) -> &str {
        &self.name
    }

    fn is_block(&self) -> bool {
        true
    }

    fn evaluate(&self, rule: &RuleWithActions, t: &mut Transaction<'_>, rm: &mut RuleMessage<'_>) {
        crate::ms_dbg_a!(t, 8, "Marking request as disruptive.");
        let rules = t.rules;
        if let Some(defaults) = rules.properties.default_actions.get(rule.get_phase() as usize) {
            for a in defaults {
                if !a.is_disruptive() {
                    continue;
                }
                a.evaluate(rule, t, rm);
            }
        }
    }
}

/// Shared helpers for the unit tests of the actions: a rule set whose debug
/// log is captured in memory, rule construction, and a `TX:` variable with
/// the dynamic-element hooks used by `setvar`.
#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::Mutex;

    use crate::debug_log::debug_log::DebugLog;
    pub use crate::rule_with_actions::RuleAction;
    use crate::rule_with_actions::{RuleWithActions, RuleWithActionsKind};
    use crate::rules_set::RulesSet;
    use crate::run_time_string::RunTimeString;
    use crate::transaction::Transaction;
    use crate::variables::variable::Variable;
    use crate::variables::{VariableSelector, new_variable};

    /// Debug log that keeps every message (level 9).
    #[derive(Default)]
    pub struct CaptureLog {
        pub lines: Mutex<Vec<String>>,
    }

    impl DebugLog for CaptureLog {
        fn write(&self, _level: i32, msg: &str) {
            self.lines.lock().unwrap().push(msg.to_string());
        }
        fn write_ctx(&self, _level: i32, _id: &str, _uri: &str, msg: &str) {
            self.lines.lock().unwrap().push(msg.to_string());
        }
        fn is_log_file_set(&self) -> bool {
            false
        }
        fn is_log_level_set(&self) -> bool {
            true
        }
        fn set_debug_log_level(&mut self, _level: i32) {}
        fn set_debug_log_file(&mut self, _file_name: &str) -> Result<(), String> {
            Ok(())
        }
        fn get_debug_log_file(&self) -> &str {
            ""
        }
        fn get_debug_log_level(&self) -> i32 {
            9
        }
        fn debug_level(&self) -> i32 {
            9
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    pub fn rules() -> RulesSet {
        RulesSet::with_debug_log(Box::new(CaptureLog::default()))
    }

    /// The debug messages logged so far.
    pub fn logs(t: &Transaction<'_>) -> Vec<String> {
        let l = t.rules.properties.debug_log.as_any().downcast_ref::<CaptureLog>().unwrap();
        l.lines.lock().unwrap().clone()
    }

    pub fn has_log(t: &Transaction<'_>, msg: &str) -> bool {
        logs(t).iter().any(|l| l == msg)
    }

    /// A `SecAction` with these actions (configuration actions applied).
    pub fn rule(actions: Vec<RuleAction>) -> RuleWithActions {
        RuleWithActions::new(Some(actions), None, "test.conf", 1, RuleWithActionsKind::Unconditional)
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
    use std::sync::Arc;

    use super::test_support::*;
    use super::*;
    use crate::actions::disruptive::deny::Deny;
    use crate::actions::disruptive::pass::Pass;
    use crate::actions::log::Log;
    use crate::actions::phase::Phase;
    use crate::modsecurity::{ModSecurity, Phases};
    use crate::rule_message::RuleMessage;

    #[test]
    fn block_runs_default_disruptive_actions() {
        let ms = ModSecurity::new();
        let mut rules = rules();
        let defaults = &mut rules.properties.default_actions[Phases::RequestBodyPhase as usize];
        defaults.push(Arc::new(Log::new("log")));
        defaults.push(Arc::new(Deny::new("deny")));
        let phase = Phase::new("phase:2").unwrap();
        let r = rule(vec![RuleAction::Phase(phase), RuleAction::Block(Block::new("block"))]);
        assert!(r.has_block_action());

        let mut t = Transaction::new(&ms, &rules, None);
        let mut rm = RuleMessage::new(&r);
        rm.save_message = false;
        Block::new("block").evaluate(&r, &mut t, &mut rm);
        assert!(has_log(&t, "Marking request as disruptive."));
        assert!(has_log(&t, "Running action deny"));
        // Only the disruptive default action ran.
        assert!(!rm.save_message);
        assert_eq!(t.intervention.status, 403);
        assert!(t.intervention.disruptive);
        assert!(rm.is_disruptive);

        // Nothing happens in a phase without default actions.
        Pass::new("pass").evaluate(&r, &mut t, &mut rm);
        let r1 = rule(vec![RuleAction::Block(Block::new("block"))]);
        Block::new("block").evaluate(&r1, &mut t, &mut rm);
        assert_eq!(t.intervention.status, 200);
    }
}
