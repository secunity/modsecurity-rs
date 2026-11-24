//! Running the actions of a rule (see [`Actions`](crate::rule::Actions)
//! for when each runs).

use super::rule::RuleRun;
use crate::actions::action::Action;
use crate::actions::context::ActionContext;
use crate::actions::rule_action::RuleAction;
use crate::rule::{Stage, stage};
use crate::rules_set::properties::RuleEngine;

impl<'a> RuleRun<'_, 'a> {
    fn context(&mut self) -> ActionContext<'_, 'a, 'a> {
        ActionContext::new(self.t, self.rule, self.rm)
    }

    /// Runs the actions that do not depend on the result of the chain, on
    /// every match of the rule: `setvar` and, for a `multiMatch` rule that
    /// is not a chain child, `severity`, `logdata`, `msg` and `tag`.
    pub(super) fn run_actions_on_match(&mut self) {
        let (rule, actions) = (self.rule, self.rule.actions());
        for a in actions.set_vars() {
            crate::ms_dbg!(self.t, 4, "Running [independent] (non-disruptive) action: {}", a.name());
            a.evaluate(&mut self.context());
        }

        if rule.has_multimatch() && !rule.chained_rule_parent {
            let describing = |a: &&RuleAction| stage(a) < Stage::Other;
            for a in actions.after_tags().iter().filter(describing) {
                a.evaluate(&mut self.context());
            }
            for a in actions.tags() {
                a.evaluate(&mut self.context());
            }
        }
    }

    /// Runs the actions of a rule whose chain matched, with what the rule
    /// set adds to them (the rule's `Link`): the `SecDefaultAction` ones,
    /// `tag`, the `SecRuleUpdateActionById` ones, then the rest in their
    /// order.
    pub(super) fn run_actions_on_chain_match(&mut self) {
        let (link, actions) = (self.link, self.rule.actions());
        for a in &link.default_actions {
            self.run_action(a, true);
        }

        for a in actions.tags() {
            crate::ms_dbg!(self.t, 4, "Running (non-disruptive) action: {}", a.name());
            a.evaluate(&mut self.context());
        }

        for a in &link.update_actions {
            self.run_action(a, false);
        }
        // A disruptive action (or a `block`) of a SecRuleUpdateActionById
        // takes the place of the rule's own.
        let updated = link.update_actions.iter().any(|a| a.is_disruptive() || matches!(**a, RuleAction::Block(_)));

        for a in actions.after_tags() {
            match stage(a) {
                // What the rule says about the match.
                Stage::Severity | Stage::LogData | Stage::Msg => a.evaluate(&mut self.context()),
                Stage::Disruptive if updated => {}
                Stage::Other if updated && matches!(a, RuleAction::Block(_)) => {}
                _ => self.run_action(a, false),
            }
        }
    }

    /// Runs one action. A disruptive action (or `block`) runs only when
    /// the rule engine is `On`, and a `block` of `SecDefaultAction`
    /// (`default_context`) only when the rule has one too.
    fn run_action(&mut self, a: &RuleAction, default_context: bool) {
        let t = &*self.t;
        if !a.is_disruptive() && !matches!(a, RuleAction::Block(_)) {
            crate::ms_dbg!(t, 9, "Running action: {}", a.name());
        } else if default_context && !self.rule.has_block_action() {
            crate::ms_dbg!(t, 4, "Ignoring action: {} (rule does not contain block)", a.name());
            return;
        } else if t.rule_engine_state() == Some(RuleEngine::Enabled) {
            crate::ms_dbg!(t, 4, "Running (disruptive)     action: {}.", a.name());
        } else {
            crate::ms_dbg!(
                t,
                4,
                "Not running any disruptive action (or block): {}. SecRuleEngine is not On.",
                a.name()
            );
            return;
        }

        let block_actions = &self.link.block_actions;
        let mut cx = self.context();
        match a {
            // `block` is the disruptive action of SecDefaultAction.
            RuleAction::Block(_) => {
                crate::ms_dbg!(cx, 8, "Marking request as disruptive.");
                for a in block_actions {
                    a.evaluate(&mut cx);
                }
            }
            a => a.evaluate(&mut cx),
        }
    }
}
