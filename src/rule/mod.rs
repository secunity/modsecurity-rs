//! A rule: `SecRule`, `SecAction` or `SecRuleScript`, with its actions and
//! transformations and how they run.
//!
//! What the three have in common is [`Rule`]; what differs is its
//! [`RuleKind`]. A chained rule owns its child (`chained_rule_child`); the
//! parent is not linked back: `chained_rule_parent` records that there is
//! one, and the transaction keeps the stack of chain ancestors during
//! evaluation (the `RULE` variable walks it). (In C++ these are the class
//! `RuleWithActions` and its three subclasses.)

mod id;
pub mod message;
pub mod sec_action;
pub mod sec_rule;
pub mod sec_rule_script;

pub use id::Id;

use crate::actions::action::{Action, Kind};
use crate::actions::context::ActionContext;
use crate::actions::log_data::LogData;
use crate::actions::msg::Msg;
use crate::actions::rule_action::RuleAction;
use crate::actions::set_var::SetVar;
use crate::actions::severity::Severity;
use crate::actions::tag::Tag;
use crate::actions::transformation::Transformation;
use crate::phases::Phases;
use crate::rule::message::RuleMessage;
use crate::rule::sec_rule::SecRule;
use crate::rule::sec_rule_script::Script;
use crate::rules_set::RulesSet;
use crate::rules_set::properties::RuleEngine;
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

/// Where [`Rule::perform_logging`] is called from (the C++
/// `lastLog` / `chainedParentNull` flags).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogPoint {
    /// A match of a `SecRule` (`lastLog = false`): logs `multiMatch` rules.
    EachMatch,
    /// The end of a matching `SecRule` (`lastLog = true`,
    /// `chainedParentNull = true`).
    RuleEnd,
    /// The end of a `SecAction` (`lastLog = true`,
    /// `chainedParentNull = false`).
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
    pub line_number: i32,
    phase: Option<Phases>,

    pub rev: String,
    pub ver: String,
    pub accuracy: i32,
    pub maturity: i32,
    pub rule_id: Id,
    pub chained_rule_child: Option<Box<Rule>>,
    pub chained_rule_parent: bool,

    disruptive_action: Option<RuleAction>,
    log_data: Option<LogData>,
    msg: Option<Msg>,
    severity: Option<Severity>,
    actions_runtime_pos: Vec<RuleAction>,
    actions_set_var: Vec<SetVar>,
    actions_tag: Vec<Tag>,
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
    /// are applied to the rule here and dropped; run time actions are sorted
    /// into their slots.
    pub fn new(
        actions: Option<Vec<RuleAction>>,
        transformations: Option<Vec<Transformation>>,
        file_name: &str,
        line_number: i32,
        kind: RuleKind,
    ) -> Self {
        let mut r = Rule {
            file_name: file_name.to_string(),
            line_number,
            phase: Some(Phases::RequestHeaders),
            rev: String::new(),
            ver: String::new(),
            accuracy: 0,
            maturity: 0,
            rule_id: Id::default(),
            chained_rule_child: None,
            chained_rule_parent: false,
            disruptive_action: None,
            log_data: None,
            msg: None,
            severity: None,
            actions_runtime_pos: Vec::new(),
            actions_set_var: Vec::new(),
            actions_tag: Vec::new(),
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
                RuleAction::Severity(a) => r.severity = Some(a),
                RuleAction::LogData(a) => r.log_data = Some(a),
                RuleAction::Msg(a) => r.msg = Some(a),
                RuleAction::SetVar(a) => r.actions_set_var.push(a),
                RuleAction::Tag(a) => r.actions_tag.push(a),
                RuleAction::Block(_) => {
                    r.actions_runtime_pos.push(a);
                    r.contains_static_block_action = true;
                }
                a => match a.kind() {
                    Kind::Configuration => {
                        a.configure(&mut r);
                    }
                    Kind::RunTimeOnlyIfMatch if a.is_disruptive() => r.disruptive_action = Some(a),
                    Kind::RunTimeOnlyIfMatch => r.actions_runtime_pos.push(a),
                    Kind::RunTimeBeforeMatchAttempt => {
                        println!("General failure, action: {} has an unknown type.", a.name());
                    }
                },
            }
        }
        r
    }

    /// The phase the rule runs in; `None` after an unknown `phase:<name>`,
    /// which leaves the rule out of every phase.
    pub fn phase(&self) -> Option<Phases> {
        self.phase
    }

    pub fn set_phase(&mut self, phase: Option<Phases>) {
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
        self.disruptive_action.is_some()
    }
    pub fn has_block_action(&self) -> bool {
        self.contains_static_block_action
    }
    pub fn has_multimatch(&self) -> bool {
        self.contains_multi_match_action
    }
    pub fn has_log_data(&self) -> bool {
        self.log_data.is_some()
    }
    pub fn has_msg(&self) -> bool {
        self.msg.is_some()
    }
    pub fn has_severity(&self) -> bool {
        self.severity.is_some()
    }

    /// The expanded `logdata` of the rule (empty without one).
    pub fn log_data(&self, t: &Transaction<'_>) -> Vec<u8> {
        self.log_data.as_ref().map(|l| l.data(t)).unwrap_or_default()
    }

    /// The expanded `msg` of the rule (empty without one).
    pub fn msg(&self, t: &Transaction<'_>) -> Vec<u8> {
        self.msg.as_ref().map(|m| m.data(t)).unwrap_or_default()
    }

    /// The `severity` of the rule (0 without one).
    pub fn severity(&self) -> i32 {
        self.severity.as_ref().map(|s| s.severity).unwrap_or(0)
    }

    pub fn disruptive_action(&self) -> Option<&RuleAction> {
        self.disruptive_action.as_ref()
    }

    pub fn transformations(&self) -> &[Transformation] {
        &self.transformations
    }

    pub fn actions_runtime_pos(&self) -> &[RuleAction] {
        &self.actions_runtime_pos
    }

    pub fn actions_tag(&self) -> &[Tag] {
        &self.actions_tag
    }

    pub fn actions_set_var(&self) -> &[SetVar] {
        &self.actions_set_var
    }

    // --- evaluation ---

    /// Evaluates the rule with a new rule message. Returns whether it
    /// matched.
    pub fn evaluate<'a>(&'a self, t: &mut Transaction<'a>) -> bool {
        let mut rm = RuleMessage::new(self);
        self.evaluate_with_message(t, &mut rm)
    }

    /// Evaluates the rule with the message `rm`, according to its kind.
    pub fn evaluate_with_message<'a>(&'a self, t: &mut Transaction<'a>, rm: &mut RuleMessage<'a>) -> bool {
        match &self.kind {
            RuleKind::SecRule(o) => o.evaluate(self, t, rm),
            RuleKind::SecAction => crate::rule::sec_action::evaluate(self, t, rm),
            RuleKind::SecRuleScript(s) => s.evaluate(self, t, rm),
        }
    }

    /// The part of the evaluation shared by every kind of rule: matched
    /// values are cleared at every new rule execution.
    pub fn evaluate_base(&self, t: &mut Transaction<'_>) {
        t.eval.matched.clear();
    }

    /// Runs the actions that do not depend on the result of the chain:
    /// `setvar` (including the ones added by `SecRuleUpdateActionById`)
    /// and, for a `multiMatch` rule that is not a chain child, `severity`,
    /// `logdata`, `msg` and `tag`. Returns whether a
    /// `SecRuleUpdateActionById` added a `block` action to the rule.
    pub fn execute_actions_independent_of_chained_rule_result<'a>(
        &'a self,
        t: &mut Transaction<'a>,
        rm: &mut RuleMessage<'a>,
    ) -> bool {
        let mut contains_block = false;
        for a in &self.actions_set_var {
            crate::ms_dbg!(t, 4, "Running [independent] (non-disruptive) action: {}", a.name());
            a.evaluate(&mut ActionContext::new(t, self, rm));
        }

        let rules = t.rules;
        for a in rules.properties.exceptions.action_pre_update_target_by_id.for_rule(self.rule_id) {
            if a.is_disruptive() && a.name() == "block" {
                crate::ms_dbg!(t, 9, "Rule contains a `block' action");
                contains_block = true;
            } else if a.name() == "setvar" {
                crate::ms_dbg!(t, 4, "Running [independent] (non-disruptive) action: {}", a.name());
                a.evaluate(&mut ActionContext::new(t, self, rm));
            }
        }

        if self.contains_multi_match_action && !self.chained_rule_parent {
            if let Some(s) = &self.severity {
                s.evaluate(&mut ActionContext::new(t, self, rm));
            }
            if let Some(l) = &self.log_data {
                l.evaluate(&mut ActionContext::new(t, self, rm));
            }
            if let Some(m) = &self.msg {
                m.evaluate(&mut ActionContext::new(t, self, rm));
            }
            for a in &self.actions_tag {
                a.evaluate(&mut ActionContext::new(t, self, rm));
            }
        }
        contains_block
    }

    /// Runs the actions of a rule whose chain matched: the
    /// `SecDefaultAction` ones that run on a match, `tag`, the ones added
    /// by `SecRuleUpdateActionById`, `severity`, `logdata`, `msg`, the
    /// other run time actions and last the disruptive action.
    pub fn execute_actions_after_full_match<'a>(
        &'a self,
        t: &mut Transaction<'a>,
        contains_block: bool,
        rm: &mut RuleMessage<'a>,
    ) {
        let mut disruptive_already_executed = false;
        let rules = t.rules;
        if let Some(defaults) = self.phase.map(|p| &rules.properties.default_actions[p.index()]) {
            for a in defaults {
                if a.kind() != Kind::RunTimeOnlyIfMatch {
                    continue;
                }
                if !a.is_disruptive() {
                    self.execute_action(t, contains_block, rm, a, true);
                }
            }
        }

        for a in &self.actions_tag {
            crate::ms_dbg!(t, 4, "Running (non-disruptive) action: {}", a.name());
            a.evaluate(&mut ActionContext::new(t, self, rm));
        }

        for a in rules.properties.exceptions.action_pos_update_target_by_id.for_rule(self.rule_id) {
            self.execute_action(t, contains_block, rm, a, false);
            disruptive_already_executed = true;
        }

        if let Some(s) = &self.severity {
            s.evaluate(&mut ActionContext::new(t, self, rm));
        }
        if let Some(l) = &self.log_data {
            l.evaluate(&mut ActionContext::new(t, self, rm));
        }
        if let Some(m) = &self.msg {
            m.evaluate(&mut ActionContext::new(t, self, rm));
        }
        for a in &self.actions_runtime_pos {
            // Neither disruptive, nor a `block` once a disruptive action ran.
            if !(a.is_disruptive() || disruptive_already_executed && matches!(a, RuleAction::Block(_))) {
                self.execute_action(t, contains_block, rm, a, false);
            }
        }
        if !disruptive_already_executed && let Some(d) = &self.disruptive_action {
            self.execute_action(t, contains_block, rm, d, false);
        }
    }

    /// Runs one action. A disruptive action (or `block`) runs only when
    /// the rule engine is `On`, and one from `SecDefaultAction`
    /// (`default_context`) only when the rule contains `block`.
    pub fn execute_action<'a>(
        &'a self,
        t: &mut Transaction<'a>,
        contains_block: bool,
        rm: &mut RuleMessage<'a>,
        a: &RuleAction,
        default_context: bool,
    ) {
        if !a.is_disruptive() && a.name() != "block" {
            crate::ms_dbg!(t, 9, "Running action: {}", a.name());
            a.evaluate(&mut ActionContext::new(t, self, rm));
            return;
        }

        if default_context && !contains_block {
            crate::ms_dbg!(t, 4, "Ignoring action: {} (rule does not cotains block)", a.name());
            return;
        }

        if t.rule_engine_state() == Some(RuleEngine::Enabled) {
            crate::ms_dbg!(t, 4, "Running (disruptive)     action: {}.", a.name());
            a.evaluate(&mut ActionContext::new(t, self, rm));
            return;
        }

        crate::ms_dbg!(t, 4, "Not running any disruptive action (or block): {}. SecRuleEngine is not On.", a.name());
    }

    /// The transformations the rule applies, in order:
    /// the `SecDefaultAction` ones (unless the rule has `t:none`), the
    /// rule's own (from its last `t:none` on) and the `SecRuleUpdateActionById`
    /// ones (likewise).
    fn for_each_transformation<'a>(&'a self, rules: &'a RulesSet, mut f: impl FnMut(&'a Transformation)) {
        let mut none = 0;

        for a in &self.transformations {
            if a.is_none() {
                none += 1;
            }
        }

        // Check for transformations on the SecDefaultAction. Notice that
        // first we make sure that won't be a t:none on the target rule.
        if none == 0
            && let Some(defaults) = self.phase.map(|p| &rules.properties.default_actions[p.index()])
        {
            for a in defaults {
                if a.kind() != Kind::RunTimeBeforeMatchAttempt {
                    continue;
                }
                if let Some(tr) = a.as_transformation() {
                    f(tr);
                }
            }
        }

        for a in &self.transformations {
            if none == 0 {
                f(a);
            }
            if a.is_none() {
                none -= 1;
            }
        }

        let pre = &rules.properties.exceptions.action_pre_update_target_by_id;
        for a in pre.for_rule(self.rule_id) {
            if a.is_transformation_none() {
                none += 1;
            }
        }
        for a in pre.for_rule(self.rule_id) {
            if let Some(tr) = a.as_transformation()
                && none == 0
            {
                f(tr);
            }
            if a.is_transformation_none() {
                none -= 1;
            }
        }
    }

    /// The transformations this rule applies with the rules of `t`, in
    /// order (see `for_each_transformation`), appended to `chain`. They are
    /// the same for every value the rule inspects.
    pub fn transformations_in<'a>(&'a self, rules: &'a RulesSet, chain: &mut Vec<&'a Transformation>) {
        self.for_each_transformation(rules, |a| chain.push(a));
    }

    /// Applies `chain` (see [`Self::transformations_in`]) to `input`.
    ///
    /// `ret` is cleared first; the buffer of its last value is reused. The
    /// path of the final value (without `multiMatch`) is
    /// [`TransformationPath::Full`], spelled out by [`Self::transformation_path`]
    /// only when it is needed (on a match).
    pub fn execute_transformations(
        &self,
        t: &Transaction<'_>,
        chain: &[&Transformation],
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
            if a.transform(&mut value, Some(t)) && multi_match {
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

    /// The names of the transformations the rule applies, joined with `,`
    /// (the C++ code builds this path for every value).
    pub fn transformation_path(&self, t: &Transaction<'_>) -> String {
        let mut path = String::new();
        self.for_each_transformation(t.rules, |a| {
            if !path.is_empty() {
                path.push(',');
            }
            path.push_str(a.name());
        });
        path
    }

    /// Whether one of the rule's `tag`s expands to `name`.
    pub fn contains_tag(&self, name: &str, t: &Transaction<'_>) -> bool {
        self.actions_tag.iter().any(|tag| *tag.string.evaluate_cow(Some(t)) == *name.as_bytes())
    }

    /// Whether the rule's `msg` expands to `name`.
    pub fn contains_msg(&self, name: &str, t: &Transaction<'_>) -> bool {
        self.msg.as_ref().is_some_and(|m| *m.string.evaluate_cow(Some(t)) == *name.as_bytes())
    }

    /// The `(prefix, href)` of the rule's `xmlns` actions, including the
    /// ones added by `SecRuleUpdateActionById`: the run time actions, then
    /// the updates before and after the match. An action counts when its
    /// name as written is `xmlns` (a transformation never is: its name
    /// starts with `t:`).
    pub fn xml_namespaces<'s>(&'s self, t: &'s Transaction<'_>) -> Vec<(&'s str, &'s str)> {
        let ex = &t.rules.properties.exceptions;
        let updates = ex.action_pre_update_target_by_id.for_rule(self.rule_id).iter().map(|a| a.as_ref());
        let updates =
            updates.chain(ex.action_pos_update_target_by_id.for_rule(self.rule_id).iter().map(|a| a.as_ref()));
        self.actions_runtime_pos
            .iter()
            .chain(updates)
            .filter_map(|a| match a {
                RuleAction::XmlNs(x) if x.name() == "xmlns" => Some(x.namespace()),
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
                // (two C++ branches with identical bodies)
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
