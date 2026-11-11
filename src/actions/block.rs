//! Port of `src/actions/block.cc`, `src/actions/block.h`.
//!
//! `block` — executes the disruptive actions of the `SecDefaultAction` of
//! the rule's phase. Rules containing it are classified by
//! `RuleWithActions` (it is kept with the run time actions and flags the
//! rule as containing a static block action).

use crate::actions::action::{Action, ActionBase};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct Block {
    pub base: ActionBase,
}

impl Block {
    pub fn new(action: &str) -> Self {
        Block { base: ActionBase::new(action) }
    }
}

impl Action for Block {
    crate::action_base_accessors!();

    fn evaluate(&self, rule: &RuleWithActions, t: &mut Transaction<'_>, rm: &mut RuleMessage<'_>) -> bool {
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
        true
    }
}

/// Shared helpers for the unit tests of the actions: a rule set whose debug
/// log is captured in memory, rule construction, and a `TX:` variable with
/// the dynamic-element hooks used by `setvar`.
#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::Mutex;

    use crate::actions::action::Action;
    use crate::collection::collection::Collection;
    use crate::debug_log::debug_log::DebugLog;
    use crate::rule_with_actions::{RuleWithActions, RuleWithActionsKind};
    use crate::rules_set::RulesSet;
    use crate::run_time_string::RunTimeString;
    use crate::transaction::Transaction;
    use crate::variable_value::VariableValue;
    use crate::variables::variable::{Variable, VariableBase};

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
        fn set_debug_log_file(&mut self, _file_name: &str, _error: &mut String) {}
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
    pub fn rule(actions: Vec<Box<dyn Action>>) -> RuleWithActions {
        RuleWithActions::new(Some(actions), None, "test.conf", 1, RuleWithActionsKind::Unconditional)
    }

    pub fn rts(s: &str) -> RunTimeString {
        RunTimeString::from_text(s)
    }

    /// Minimal `Tx_DynamicElement` (`TX:<name>`).
    #[derive(Debug)]
    pub struct TestTx {
        base: VariableBase,
        string: RunTimeString,
    }

    impl TestTx {
        pub fn new(name: &str) -> Self {
            TestTx { base: VariableBase::new(&format!("TX:{}", name)), string: rts(name) }
        }
    }

    impl Variable for TestTx {
        fn base(&self) -> &VariableBase {
            &self.base
        }
        fn base_mut(&mut self) -> &mut VariableBase {
            &mut self.base
        }
        fn evaluate(&self, t: &Transaction<'_>, _rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
            let name = self.string.evaluate(Some(t));
            if let Some(v) = t.collections.tx_collection.resolve_first(&name) {
                l.push(VariableValue::new(&name, &v));
            }
        }
        fn dynamic_name(&self) -> Option<&RunTimeString> {
            Some(&self.string)
        }
        fn dynamic_del(&self, t: &Transaction<'_>, key: &[u8]) {
            t.collections.tx_collection.del(key);
        }
        fn dynamic_store_or_update_first(&self, t: &Transaction<'_>, key: &[u8], value: &[u8]) {
            t.collections.tx_collection.store_or_update_first(key, value);
        }
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
        let mut phase = Phase::new("phase:2");
        phase.init().unwrap();
        let r = rule(vec![Box::new(phase), Box::new(Block::new("block"))]);
        assert!(r.has_block_action());

        let mut t = Transaction::new(&ms, &rules, None);
        let mut rm = RuleMessage::new(&r);
        rm.save_message = false;
        Block::new("block").evaluate(&r, &mut t, &mut rm);
        assert!(has_log(&t, "Marking request as disruptive."));
        assert!(has_log(&t, "Running action deny"));
        // Only the disruptive default action ran.
        assert!(!rm.save_message);
        assert_eq!(t.it.status, 403);
        assert_eq!(t.it.disruptive, 1);
        assert!(rm.is_disruptive);

        // Nothing happens in a phase without default actions.
        Pass::new("pass").evaluate(&r, &mut t, &mut rm);
        let r1 = rule(vec![Box::new(Block::new("block"))]);
        Block::new("block").evaluate(&r1, &mut t, &mut rm);
        assert_eq!(t.it.status, 200);
    }
}
