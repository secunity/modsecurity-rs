//! One rule being evaluated, of any kind: [`RuleRun`].

use crate::actions::action::Action;
use crate::actions::transformation::Transformation;
use crate::rule::message::RuleMessage;
use crate::rule::sec_rule_script::Script;
use crate::rule::{LogPoint, Rule, RuleKind, TransformationPath, TransformationResults};
use crate::rules_set::plan::Link;
use crate::transaction::Transaction;
use crate::utils::string::limit_to;

/// Evaluates `rule` with a new rule message. `chain` is the plan of the
/// rule and of the rules chained to it. Returns whether it matched.
pub(crate) fn run<'a>(rule: &'a Rule, chain: &'a [Link], t: &mut Transaction<'a>) -> bool {
    let mut rm = RuleMessage::new(rule);
    RuleRun::new(rule, chain, t, &mut rm).run()
}

/// The evaluation of one rule: the rule, its plan, the transaction, and the
/// message the rules of its chain write to.
pub(super) struct RuleRun<'r, 'a> {
    pub(super) rule: &'a Rule,
    /// The plan of the rule.
    pub(super) link: &'a Link,
    /// The plan of the rules chained to it.
    pub(super) chained: &'a [Link],
    pub(super) t: &'r mut Transaction<'a>,
    pub(super) rm: &'r mut RuleMessage<'a>,
}

impl<'r, 'a> RuleRun<'r, 'a> {
    pub(super) fn new(
        rule: &'a Rule,
        chain: &'a [Link],
        t: &'r mut Transaction<'a>,
        rm: &'r mut RuleMessage<'a>,
    ) -> Self {
        let (link, chained) = chain.split_first().expect("the plan of the rule");
        RuleRun { rule, link, chained, t, rm }
    }

    /// Evaluates the rule according to its kind.
    pub(super) fn run(&mut self) -> bool {
        match &self.rule.kind {
            RuleKind::SecRule(r) => self.sec_rule(r),
            RuleKind::SecAction => self.sec_action(),
            RuleKind::SecRuleScript(s) => self.script(s),
        }
    }

    /// A `SecAction`: runs its actions and logs it. It always matches.
    fn sec_action(&mut self) -> bool {
        self.clear_matched();
        crate::ms_dbg!(self.t, 4, "(Rule: {}) Executing unconditional rule...", self.rule.logged_id());
        self.run_actions_on_match();
        self.run_actions_on_chain_match();
        self.log(LogPoint::UnconditionalEnd);
        true
    }

    /// A `SecRuleScript`: it matches when the script's `main` returns a
    /// non empty string (or number). (It keeps the matched values of the
    /// rule before it.)
    fn script(&mut self, script: &Script) -> bool {
        crate::ms_dbg!(self.t, 4, " Executing script: {}.", script.name);
        self.run_actions_on_match();
        let ret = script.lua.run(self.t, b"");
        if ret {
            self.run_actions_on_chain_match();
        }
        ret
    }

    /// Clears the values the operator matched (for `capture`) at the
    /// start of a `SecRule` or `SecAction`.
    pub(super) fn clear_matched(&mut self) {
        self.t.eval.matched.clear();
    }

    /// Applies `chain` (the transformations of the rule's [`Link`]) to
    /// `input`.
    ///
    /// `ret` is cleared first; the buffer of its last value is reused. The
    /// path of the final value (without `multiMatch`) is
    /// [`TransformationPath::Full`]: the path of the rule's [`Link`].
    pub(super) fn transform(&self, chain: &[Transformation], input: &[u8], ret: &mut TransformationResults) {
        let t = &*self.t;
        let multi_match = self.rule.has_multimatch();
        let mut value = match ret.pop() {
            Some((mut v, _)) => {
                v.clear();
                v.extend_from_slice(input);
                v
            }
            None => input.to_vec(),
        };
        ret.clear();
        let mut nth = 0;

        if multi_match {
            // The original value is inspected too.
            ret.push((value.clone(), TransformationPath::Step(String::new())));
        }

        for a in chain {
            a.transform(&mut value, Some(t));
            // With multiMatch, every value a transformation produced is
            // inspected: the ones that differ from the value before it.
            if multi_match && ret.last().is_some_and(|(before, _)| *before != value) {
                ret.push((value.clone(), TransformationPath::Step(a.name().to_string())));
                nth += 1;
            }
            crate::ms_dbg!(t, 9, " T ({}) {}: \"{}\"", nth, a.name(), String::from_utf8_lossy(&limit_to(80, &value)));
        }

        if multi_match {
            crate::ms_dbg!(t, 9, "multiMatch is enabled. {} values to be tested.", ret.len());
        } else {
            ret.push((value, TransformationPath::Full));
        }
    }

    /// Saves the message for the audit log and sends it to the server log,
    /// depending on where the rule is in its evaluation.
    pub(super) fn log(&mut self, point: LogPoint) {
        let rule = self.rule;
        let rm = &mut *self.rm;
        let t = &mut *self.t;
        let mut is_it_to_be_logged = rm.save_message;
        if point != LogPoint::EachMatch {
            if point == LogPoint::RuleEnd {
                is_it_to_be_logged = rm.save_message && !rule.chain.is_continuation;
                if is_it_to_be_logged && !rule.has_multimatch() {
                    t.outcome.rules_messages.push(rm.clone());
                    if !rm.is_disruptive {
                        t.server_log(rm);
                    }
                }
            } else if (rule.has_block_action() && !rule.has_multimatch())
                || (is_it_to_be_logged && !rule.has_multimatch() && !rm.message.is_empty())
            {
                t.outcome.rules_messages.push(rm.clone());
                if !rm.is_disruptive {
                    t.server_log(rm);
                }
            }
        } else if rule.has_multimatch() && is_it_to_be_logged {
            t.outcome.rules_messages.push(rm.clone());
            if !rm.is_disruptive {
                t.server_log(rm);
            }
            rm.reset(false);
        }
    }
}
