//! A rule: `SecRule`, `SecAction` or `SecRuleScript`, with its actions and
//! transformations and how they run.
//!
//! What the three have in common is [`Rule`]; what differs is its
//! [`RuleKind`]. A chained rule owns its child (`chained_rule_child`); the
//! parent is not linked back: `chained_rule_parent` records that there is
//! one, and the transaction keeps the stack of chain ancestors during
//! evaluation (the `RULE` variable walks it).

mod actions;
pub mod id;
pub mod message;
pub mod sec_action;
pub mod sec_rule;
pub mod sec_rule_script;

pub use actions::Actions;
pub use id::Id;

use crate::actions::action::{Action, Kind};
use crate::actions::rule_action::RuleAction;
use crate::actions::transformation::Transformation;
use crate::phases::Phases;
use crate::rule::message::RuleMessage;
use crate::rule::sec_rule::SecRule;
use crate::rule::sec_rule_script::Script;
use crate::rules_set::plan::Link;
use crate::transaction::Transaction;
use crate::utils::string::limit_to;

/// A transformed value and the transformation path that produced it
/// (e.g. `t:lowercase,t:urlDecode`).
pub type TransformationResult = (Vec<u8>, TransformationPath);

/// The transformation path of a [`TransformationResult`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransformationPath {
    /// With `multiMatch`: the original value (empty path) or the one
    /// transformation that produced this value.
    Step(String),
    /// All the transformations of the rule (see
    /// [`Rule::transformation_path`]).
    Full,
}
pub type TransformationResults = Vec<TransformationResult>;

/// Where [`Rule::perform_logging`] is called from, which decides
/// whether the message is logged there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogPoint {
    /// A match of a `SecRule`: logs `multiMatch` rules.
    EachMatch,
    /// The end of a matching `SecRule`: logs the other rules, unless
    /// the rule is a chained child.
    RuleEnd,
    /// The end of a `SecAction`: logs a rule with a block action, or
    /// one to be logged that has a message.
    UnconditionalEnd,
}

/// Which directive a rule is, with what only that kind has.
#[derive(Debug)]
pub enum RuleKind {
    /// A `SecRule`: its variables and operator.
    SecRule(SecRule),
    /// A `SecAction`: actions only; it always matches.
    SecAction,
    /// A `SecRuleScript`: its Lua script.
    SecRuleScript(Script),
}

/// A rule of a configuration.
#[derive(Debug)]
pub struct Rule {
    /// Where the rule was read.
    pub file_name: String,
    pub line_number: usize,
    phase: Phases,

    pub rev: String,
    pub ver: String,
    pub accuracy: u8,
    pub maturity: u8,
    pub rule_id: Id,
    pub chained_rule_child: Option<Box<Rule>>,
    pub chained_rule_parent: bool,

    actions: Actions,
    transformations: Vec<Transformation>,

    contains_capture_action: bool,
    contains_multi_match_action: bool,
    contains_static_block_action: bool,
    is_chained: bool,

    pub kind: RuleKind,
}

impl Rule {
    /// Builds a rule from its parsed actions and transformations and its
    /// kind specific part. Configuration actions (`id`, `phase`, ...)
    /// are applied to the rule here and dropped; the run time actions are
    /// its [`Actions`].
    pub fn new(
        actions: Option<Vec<RuleAction>>,
        transformations: Option<Vec<Transformation>>,
        file_name: &str,
        line_number: usize,
        kind: RuleKind,
    ) -> Self {
        let mut r = Rule {
            file_name: file_name.to_string(),
            line_number,
            phase: Phases::RequestHeaders,
            rev: String::new(),
            ver: String::new(),
            accuracy: 0,
            maturity: 0,
            rule_id: Id::default(),
            chained_rule_child: None,
            chained_rule_parent: false,
            actions: Actions::default(),
            transformations: transformations.unwrap_or_default(),
            contains_capture_action: false,
            contains_multi_match_action: false,
            contains_static_block_action: false,
            is_chained: false,
            kind,
        };
        for a in actions.into_iter().flatten() {
            match a {
                // The only configuration action with a type of its own.
                RuleAction::Phase(p) => {
                    p.configure(&mut r);
                }
                RuleAction::Capture(_) => r.contains_capture_action = true,
                RuleAction::MultiMatch(_) => r.contains_multi_match_action = true,
                RuleAction::Block(_) => {
                    r.contains_static_block_action = true;
                    r.actions.add(a);
                }
                a => match a.kind() {
                    Kind::Configuration => {
                        a.configure(&mut r);
                    }
                    Kind::RunTimeOnlyIfMatch => r.actions.add(a),
                    // A transformation given with the actions.
                    Kind::RunTimeBeforeMatchAttempt => {
                        if let RuleAction::Transformation(t) = a {
                            r.transformations.push(t);
                        }
                    }
                },
            }
        }
        r
    }

    /// The phase the rule runs in.
    pub fn phase(&self) -> Phases {
        self.phase
    }

    pub fn set_phase(&mut self, phase: Phases) {
        self.phase = phase;
    }

    /// The rule id for `SecRule`s, `file:line` otherwise.
    pub fn reference(&self) -> String {
        match self.kind {
            RuleKind::SecRule(_) => self.rule_id.to_string(),
            _ => format!("{}:{}", self.file_name, self.line_number),
        }
    }

    pub fn is_sec_rule(&self) -> bool {
        matches!(self.kind, RuleKind::SecRule(_))
    }

    pub fn as_sec_rule(&self) -> Option<&SecRule> {
        match &self.kind {
            RuleKind::SecRule(o) => Some(o),
            _ => None,
        }
    }

    pub fn as_rule_script(&self) -> Option<&Script> {
        match &self.kind {
            RuleKind::SecRuleScript(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_rule_script_mut(&mut self) -> Option<&mut Script> {
        match &mut self.kind {
            RuleKind::SecRuleScript(s) => Some(s),
            _ => None,
        }
    }

    // --- flags ---

    pub fn is_chained(&self) -> bool {
        self.is_chained
    }
    pub fn has_capture_action(&self) -> bool {
        self.contains_capture_action
    }
    pub fn set_chained(&mut self, b: bool) {
        self.is_chained = b;
    }
    pub fn has_disruptive_action(&self) -> bool {
        self.actions.disruptive().is_some()
    }
    pub fn has_block_action(&self) -> bool {
        self.contains_static_block_action
    }
    pub fn has_multimatch(&self) -> bool {
        self.contains_multi_match_action
    }
    pub fn has_log_data(&self) -> bool {
        self.actions.log_data().is_some()
    }
    pub fn has_msg(&self) -> bool {
        self.actions.msg().is_some()
    }
    pub fn has_severity(&self) -> bool {
        self.actions.severity().is_some()
    }

    /// The expanded `logdata` of the rule (empty without one).
    pub fn log_data(&self, t: &Transaction<'_>) -> Vec<u8> {
        self.actions.log_data().map(|l| l.data(t)).unwrap_or_default()
    }

    /// The expanded `msg` of the rule (empty without one).
    pub fn msg(&self, t: &Transaction<'_>) -> Vec<u8> {
        self.actions.msg().map(|m| m.data(t)).unwrap_or_default()
    }

    /// The `severity` of the rule (0 without one).
    pub fn severity(&self) -> u8 {
        self.actions.severity().map(|s| s.severity).unwrap_or(0)
    }

    pub fn transformations(&self) -> &[Transformation] {
        &self.transformations
    }

    /// The run time actions of the rule.
    pub fn actions(&self) -> &Actions {
        &self.actions
    }

    // --- evaluation ---

    /// Evaluates the rule with a new rule message. `chain` is the plan of
    /// the rule and of the rules chained to it. Returns whether it
    /// matched.
    pub fn evaluate<'a>(&'a self, chain: &'a [Link], t: &mut Transaction<'a>) -> bool {
        let mut rm = RuleMessage::new(self);
        self.evaluate_with_message(chain, t, &mut rm)
    }

    /// Evaluates the rule with the message `rm`, according to its kind.
    pub fn evaluate_with_message<'a>(
        &'a self,
        chain: &'a [Link],
        t: &mut Transaction<'a>,
        rm: &mut RuleMessage<'a>,
    ) -> bool {
        match &self.kind {
            RuleKind::SecRule(o) => o.evaluate(self, chain, t, rm),
            RuleKind::SecAction => crate::rule::sec_action::evaluate(self, &chain[0], t, rm),
            RuleKind::SecRuleScript(s) => s.evaluate(self, &chain[0], t, rm),
        }
    }

    /// The part of the evaluation shared by every kind of rule: matched
    /// values are cleared at every new rule execution.
    pub fn evaluate_base(&self, t: &mut Transaction<'_>) {
        t.eval.matched.clear();
    }

    /// Applies `chain` (the transformations of the rule's [`Link`]) to
    /// `input`.
    ///
    /// `ret` is cleared first; the buffer of its last value is reused. The
    /// path of the final value (without `multiMatch`) is
    /// [`TransformationPath::Full`]: the path of the rule's [`Link`].
    pub fn execute_transformations(
        &self,
        t: &Transaction<'_>,
        chain: &[Transformation],
        input: &[u8],
        ret: &mut TransformationResults,
    ) {
        let multi_match = self.contains_multi_match_action;
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
            // keep the original value
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

    /// Whether the rule has the tag `name`, as written: a macro in a tag
    /// expands to nothing here (this is asked of a rule set, outside of
    /// any transaction).
    pub fn has_tag(&self, name: &str) -> bool {
        self.actions.tags().any(|tag| *tag.string.evaluate_cow(None) == *name.as_bytes())
    }

    /// Whether the rule's `msg` is `name`, as written (see
    /// [`Self::has_tag`]).
    pub fn msg_is(&self, name: &str) -> bool {
        self.actions.msg().is_some_and(|m| *m.string.evaluate_cow(None) == *name.as_bytes())
    }

    /// Whether one of the rule's `tag`s expands to `name`.
    pub fn contains_tag(&self, name: &str, t: &Transaction<'_>) -> bool {
        self.actions.tags().any(|tag| *tag.string.evaluate_cow(Some(t)) == *name.as_bytes())
    }

    /// Whether the rule's `msg` expands to `name`.
    pub fn contains_msg(&self, name: &str, t: &Transaction<'_>) -> bool {
        self.actions.msg().is_some_and(|m| *m.string.evaluate_cow(Some(t)) == *name.as_bytes())
    }

    /// The `(prefix, href)` of the rule's `xmlns` actions, including the
    /// ones added by `SecRuleUpdateActionById`: the run time actions, then
    /// the added ones.
    pub fn xml_namespaces<'s>(&'s self, t: &'s Transaction<'_>) -> Vec<(&'s str, &'s str)> {
        let ex = &t.rules.properties.exceptions;
        let updates = ex.action_pos_update_target_by_id.for_rule(self.rule_id).iter().map(|a| a.as_ref());
        self.actions
            .after_tags()
            .iter()
            .chain(updates)
            .filter_map(|a| match a {
                RuleAction::XmlNs(x) => Some(x.namespace()),
                _ => None,
            })
            .collect()
    }

    /// Saves the message for the audit log and sends it to the server log,
    /// depending on where the rule is in its evaluation.
    pub fn perform_logging<'a>(&'a self, t: &mut Transaction<'a>, rm: &mut RuleMessage<'a>, point: LogPoint) {
        let mut is_it_to_be_logged = rm.save_message;
        if point != LogPoint::EachMatch {
            if point == LogPoint::RuleEnd {
                is_it_to_be_logged = rm.save_message && !self.chained_rule_parent;
                if is_it_to_be_logged && !self.has_multimatch() {
                    t.outcome.rules_messages.push(rm.clone());
                    if !rm.is_disruptive {
                        t.server_log(rm);
                    }
                }
            } else if (self.has_block_action() && !self.has_multimatch())
                || (is_it_to_be_logged && !self.has_multimatch() && !rm.message.is_empty())
            {
                t.outcome.rules_messages.push(rm.clone());
                if !rm.is_disruptive {
                    t.server_log(rm);
                }
            }
        } else if self.has_multimatch() && is_it_to_be_logged {
            t.outcome.rules_messages.push(rm.clone());
            if !rm.is_disruptive {
                t.server_log(rm);
            }
            rm.reset(false);
        }
    }
}
