//! Port of `headers/modsecurity/rule_with_actions.h` and
//! `src/rule_with_actions.cc`.
//!
//! C++ has `RuleWithActions : Rule` with three subclasses
//! (`RuleWithOperator`, `RuleUnconditional`, `RuleScript`). Here the shared
//! part is this struct and the subclass specific part is
//! [`RuleWithActionsKind`]. A chained rule owns its child
//! (`chained_rule_child`); the C++ back pointer to the parent is replaced by
//! `chained_rule_parent` (a flag, since only its presence is tested by the
//! rule itself) plus the stack of chain ancestors kept by the transaction
//! during evaluation (used by the `RULE` variable to walk up the chain).

use crate::actions::action::{Action, Kind};
use crate::actions::block::Block;
use crate::actions::capture::Capture;
use crate::actions::log_data::LogData;
use crate::actions::msg::Msg;
use crate::actions::multi_match::MultiMatch;
use crate::actions::set_var::SetVar;
use crate::actions::severity::Severity;
use crate::actions::tag::Tag;
use crate::actions::transformations::transformation::Transformation;
use crate::modsecurity::Phases;
use crate::rule_message::RuleMessage;
use crate::rule_script::RuleScript;
use crate::rule_with_operator::RuleWithOperator;
use crate::rules_set_properties::RuleEngine;
use crate::transaction::Transaction;
use crate::utils::string::limit_to;

/// `TransformationResult`: the transformed value and the transformation
/// path that produced it (e.g. `t:lowercase,t:urlDecode`).
pub type TransformationResult = (Vec<u8>, TransformationPath);

/// The transformation path of a [`TransformationResult`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransformationPath {
    /// `multiMatch`: the original value (empty path) or the one
    /// transformation that produced this value.
    Step(String),
    /// All the transformations of the rule (see
    /// [`RuleWithActions::transformation_path`]).
    Full,
}
pub type TransformationResults = Vec<TransformationResult>;

/// The subclass specific part of a rule.
#[derive(Debug)]
pub enum RuleWithActionsKind {
    /// `RuleWithOperator` (`SecRule`)
    Operator(RuleWithOperator),
    /// `RuleUnconditional` (`SecAction`)
    Unconditional,
    /// `RuleScript` (`SecRuleScript`)
    Script(RuleScript),
}

#[derive(Debug)]
pub struct RuleWithActions {
    // --- `Rule` ---
    pub file_name: String,
    pub line_number: i32,
    phase: i32,

    // --- `RuleWithActions` ---
    pub rev: String,
    pub ver: String,
    pub accuracy: i32,
    pub maturity: i32,
    pub rule_id: i64,
    pub chained_rule_child: Option<Box<RuleWithActions>>,
    pub chained_rule_parent: bool,

    disruptive_action: Option<Box<dyn Action>>,
    log_data: Option<Box<LogData>>,
    msg: Option<Box<Msg>>,
    severity: Option<Box<Severity>>,
    actions_runtime_pos: Vec<Box<dyn Action>>,
    actions_set_var: Vec<SetVar>,
    actions_tag: Vec<Tag>,
    transformations: Vec<Box<dyn Transformation>>,

    contains_capture_action: bool,
    contains_multi_match_action: bool,
    contains_static_block_action: bool,
    is_chained: bool,

    pub kind: RuleWithActionsKind,
}

/// Moves a boxed action into its concrete type (`dynamic_cast` + ownership
/// transfer). The caller checks the type first.
fn downcast_box<T: Action>(a: Box<dyn Action>) -> Box<T> {
    let any: Box<dyn std::any::Any> = a;
    any.downcast::<T>().expect("type checked by caller")
}

impl RuleWithActions {
    /// `RuleWithActions(actions, transformations, fileName, lineNumber)`
    /// plus the subclass part. Configuration actions (`id`, `phase`, ...)
    /// are applied to the rule here and dropped; run time actions are sorted
    /// into their slots.
    pub fn new(
        actions: Option<Vec<Box<dyn Action>>>,
        transformations: Option<Vec<Box<dyn Transformation>>>,
        file_name: &str,
        line_number: i32,
        kind: RuleWithActionsKind,
    ) -> Self {
        let mut r = RuleWithActions {
            file_name: file_name.to_string(),
            line_number,
            phase: Phases::RequestHeadersPhase as i32,
            rev: String::new(),
            ver: String::new(),
            accuracy: 0,
            maturity: 0,
            rule_id: 0,
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
        if let Some(actions) = actions {
            for a in actions {
                match a.action_kind() {
                    Kind::ConfigurationKind => {
                        a.configure(&mut r);
                    }
                    Kind::RunTimeOnlyIfMatchKind => {
                        if a.is::<Capture>() {
                            r.contains_capture_action = true;
                        } else if a.is::<MultiMatch>() {
                            r.contains_multi_match_action = true;
                        } else if a.is::<Severity>() {
                            r.severity = Some(downcast_box(a));
                        } else if a.is::<LogData>() {
                            r.log_data = Some(downcast_box(a));
                        } else if a.is::<Msg>() {
                            r.msg = Some(downcast_box(a));
                        } else if a.is::<SetVar>() {
                            r.actions_set_var.push(*downcast_box(a));
                        } else if a.is::<Tag>() {
                            r.actions_tag.push(*downcast_box(a));
                        } else if a.is::<Block>() {
                            r.actions_runtime_pos.push(a);
                            r.contains_static_block_action = true;
                        } else if a.is_disruptive() {
                            r.disruptive_action = Some(a);
                        } else {
                            r.actions_runtime_pos.push(a);
                        }
                    }
                    Kind::RunTimeBeforeMatchAttemptKind => {
                        println!("General failure, action: {} has an unknown type.", a.name());
                    }
                }
            }
        }
        r
    }

    // --- `Rule` accessors ---

    pub fn get_phase(&self) -> i32 {
        self.phase
    }

    pub fn set_phase(&mut self, phase: i32) {
        self.phase = phase;
    }

    /// `getReference`: the rule id for `SecRule`s, `file:line` otherwise.
    pub fn get_reference(&self) -> String {
        match self.kind {
            RuleWithActionsKind::Operator(_) => self.rule_id.to_string(),
            _ => format!("{}:{}", self.file_name, self.line_number),
        }
    }

    pub fn is_rule_with_operator(&self) -> bool {
        matches!(self.kind, RuleWithActionsKind::Operator(_))
    }

    pub fn as_rule_with_operator(&self) -> Option<&RuleWithOperator> {
        match &self.kind {
            RuleWithActionsKind::Operator(o) => Some(o),
            _ => None,
        }
    }

    pub fn as_rule_script(&self) -> Option<&RuleScript> {
        match &self.kind {
            RuleWithActionsKind::Script(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_rule_script_mut(&mut self) -> Option<&mut RuleScript> {
        match &mut self.kind {
            RuleWithActionsKind::Script(s) => Some(s),
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

    /// `logData(t)`
    pub fn log_data(&self, t: &Transaction<'_>) -> Vec<u8> {
        self.log_data.as_ref().map(|l| l.data(t)).unwrap_or_default()
    }

    /// `msg(t)`
    pub fn msg(&self, t: &Transaction<'_>) -> Vec<u8> {
        self.msg.as_ref().map(|m| m.data(t)).unwrap_or_default()
    }

    /// `severity()`
    pub fn severity(&self) -> i32 {
        self.severity.as_ref().map(|s| s.severity).unwrap_or(0)
    }

    pub fn disruptive_action(&self) -> Option<&dyn Action> {
        self.disruptive_action.as_deref()
    }

    pub fn transformations(&self) -> &[Box<dyn Transformation>] {
        &self.transformations
    }

    pub fn actions_runtime_pos(&self) -> &[Box<dyn Action>] {
        &self.actions_runtime_pos
    }

    pub fn actions_tag(&self) -> &[Tag] {
        &self.actions_tag
    }

    pub fn actions_set_var(&self) -> &[SetVar] {
        &self.actions_set_var
    }

    // --- evaluation ---

    /// `evaluate(transaction)`
    pub fn evaluate<'a>(&'a self, t: &mut Transaction<'a>) -> bool {
        let mut rm = RuleMessage::new(self);
        self.evaluate_with_message(t, &mut rm)
    }

    /// `evaluate(transaction, ruleMessage)`: dispatches to the subclass.
    pub fn evaluate_with_message<'a>(&'a self, t: &mut Transaction<'a>, rm: &mut RuleMessage<'a>) -> bool {
        match &self.kind {
            RuleWithActionsKind::Operator(o) => o.evaluate(self, t, rm),
            RuleWithActionsKind::Unconditional => crate::rule_unconditional::evaluate(self, t, rm),
            RuleWithActionsKind::Script(s) => s.evaluate(self, t, rm),
        }
    }

    /// The `RuleWithActions::evaluate` body shared by the subclasses:
    /// matched values are cleared at every new rule execution.
    pub fn evaluate_base(&self, t: &mut Transaction<'_>) {
        t.matched.clear();
    }

    /// `executeActionsIndependentOfChainedRuleResult`
    pub fn execute_actions_independent_of_chained_rule_result<'a>(
        &'a self,
        t: &mut Transaction<'a>,
        contains_block: &mut bool,
        rm: &mut RuleMessage<'a>,
    ) {
        for a in &self.actions_set_var {
            crate::ms_dbg_a!(t, 4, "Running [independent] (non-disruptive) action: {}", a.name());
            a.evaluate(self, t, rm);
        }

        let rules = t.rules;
        for a in rules.properties.exceptions.action_pre_update_target_by_id.for_id(self.rule_id as f64) {
            if a.is_disruptive() && a.name() == "block" {
                crate::ms_dbg_a!(t, 9, "Rule contains a `block' action");
                *contains_block = true;
            } else if a.name() == "setvar" {
                crate::ms_dbg_a!(t, 4, "Running [independent] (non-disruptive) action: {}", a.name());
                a.evaluate(self, t, rm);
            }
        }

        if self.contains_multi_match_action && !self.chained_rule_parent {
            if let Some(s) = &self.severity {
                s.evaluate(self, t, rm);
            }
            if let Some(l) = &self.log_data {
                l.evaluate(self, t, rm);
            }
            if let Some(m) = &self.msg {
                m.evaluate(self, t, rm);
            }
            for a in &self.actions_tag {
                a.evaluate(self, t, rm);
            }
        }
    }

    /// `executeActionsAfterFullMatch`
    pub fn execute_actions_after_full_match<'a>(
        &'a self,
        t: &mut Transaction<'a>,
        contains_block: bool,
        rm: &mut RuleMessage<'a>,
    ) {
        let mut disruptive_already_executed = false;
        let rules = t.rules;
        let phase = self.get_phase() as usize;
        if let Some(defaults) = rules.properties.default_actions.get(phase) {
            for a in defaults {
                if a.action_kind() != Kind::RunTimeOnlyIfMatchKind {
                    continue;
                }
                if !a.is_disruptive() {
                    self.execute_action(t, contains_block, rm, a.as_ref(), true);
                }
            }
        }

        for a in &self.actions_tag {
            crate::ms_dbg_a!(t, 4, "Running (non-disruptive) action: {}", a.name());
            a.evaluate(self, t, rm);
        }

        for a in rules.properties.exceptions.action_pos_update_target_by_id.for_id(self.rule_id as f64) {
            self.execute_action(t, contains_block, rm, a.as_ref(), false);
            disruptive_already_executed = true;
        }

        if let Some(s) = &self.severity {
            s.evaluate(self, t, rm);
        }
        if let Some(l) = &self.log_data {
            l.evaluate(self, t, rm);
        }
        if let Some(m) = &self.msg {
            m.evaluate(self, t, rm);
        }
        for a in &self.actions_runtime_pos {
            if !a.is_disruptive() && !(disruptive_already_executed && a.is::<Block>()) {
                self.execute_action(t, contains_block, rm, a.as_ref(), false);
            }
        }
        if !disruptive_already_executed && let Some(d) = &self.disruptive_action {
            self.execute_action(t, contains_block, rm, d.as_ref(), false);
        }
    }

    /// `executeAction`
    pub fn execute_action<'a>(
        &'a self,
        t: &mut Transaction<'a>,
        contains_block: bool,
        rm: &mut RuleMessage<'a>,
        a: &dyn Action,
        default_context: bool,
    ) {
        if !a.is_disruptive() && a.name() != "block" {
            crate::ms_dbg_a!(t, 9, "Running action: {}", a.name());
            a.evaluate(self, t, rm);
            return;
        }

        if default_context && !contains_block {
            crate::ms_dbg_a!(t, 4, "Ignoring action: {} (rule does not cotains block)", a.name());
            return;
        }

        if t.get_rule_engine_state() == RuleEngine::EnabledRuleEngine {
            crate::ms_dbg_a!(t, 4, "Running (disruptive)     action: {}.", a.name());
            a.evaluate(self, t, rm);
            return;
        }

        crate::ms_dbg_a!(t, 4, "Not running any disruptive action (or block): {}. SecRuleEngine is not On.", a.name());
    }

    /// The transformations `executeTransformations` applies, in order:
    /// the `SecDefaultAction` ones (unless the rule has `t:none`), the
    /// rule's own (from its last `t:none` on) and the `SecRuleUpdateActionById`
    /// ones (likewise).
    fn for_each_transformation(&self, t: &Transaction<'_>, mut f: impl FnMut(&dyn Transformation)) {
        let mut none = 0;

        for a in &self.transformations {
            if a.base().is_none {
                none += 1;
            }
        }

        // Check for transformations on the SecDefaultAction. Notice that
        // first we make sure that won't be a t:none on the target rule.
        let rules = t.rules;
        if none == 0
            && let Some(defaults) = rules.properties.default_actions.get(self.get_phase() as usize)
        {
            for a in defaults {
                if a.action_kind() != Kind::RunTimeBeforeMatchAttemptKind {
                    continue;
                }
                if let Some(tr) = a.as_transformation() {
                    f(tr);
                }
            }
        }

        for a in &self.transformations {
            if none == 0 {
                f(a.as_ref());
            }
            if a.base().is_none {
                none -= 1;
            }
        }

        let pre = &rules.properties.exceptions.action_pre_update_target_by_id;
        for a in pre.for_id(self.rule_id as f64) {
            if a.base().is_none {
                none += 1;
            }
        }
        for a in pre.for_id(self.rule_id as f64) {
            if let Some(tr) = a.as_transformation()
                && none == 0
            {
                f(tr);
            }
            if a.base().is_none {
                none -= 1;
            }
        }
    }

    /// `executeTransformations` (with `executeTransformation` inlined).
    ///
    /// `ret` is cleared first; the buffer of its last value is reused. The
    /// path of the final value (without `multiMatch`) is
    /// [`TransformationPath::Full`], spelled out by [`Self::transformation_path`]
    /// only when it is needed (on a match).
    pub fn execute_transformations(&self, t: &Transaction<'_>, input: &[u8], ret: &mut TransformationResults) {
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

        self.for_each_transformation(t, |a| {
            if a.transform(&mut value, Some(t)) && multi_match {
                ret.push((value.clone(), TransformationPath::Step(a.name().to_string())));
                nth += 1;
            }
            crate::ms_dbg_a!(t, 9, " T ({}) {}: \"{}\"", nth, a.name(), String::from_utf8_lossy(&limit_to(80, &value)));
        });

        if multi_match {
            crate::ms_dbg_a!(t, 9, "multiMatch is enabled. {} values to be tested.", ret.len());
        } else {
            ret.push((value, TransformationPath::Full));
        }
    }

    /// The names of the transformations `executeTransformations` applies,
    /// joined with `,` (the C++ code builds this path for every value).
    pub fn transformation_path(&self, t: &Transaction<'_>) -> String {
        let mut path = String::new();
        self.for_each_transformation(t, |a| {
            if !path.is_empty() {
                path.push(',');
            }
            path.push_str(a.name());
        });
        path
    }

    /// `containsTag`
    pub fn contains_tag(&self, name: &str, t: &Transaction<'_>) -> bool {
        self.actions_tag.iter().any(|tag| *tag.string.evaluate_cow(Some(t)) == *name.as_bytes())
    }

    /// `containsMsg`
    pub fn contains_msg(&self, name: &str, t: &Transaction<'_>) -> bool {
        self.msg.as_ref().is_some_and(|m| *m.string.evaluate_cow(Some(t)) == *name.as_bytes())
    }

    /// `getActionsByName`
    pub fn get_actions_by_name<'s>(&'s self, name: &str, t: &'s Transaction<'_>) -> Vec<&'s dyn Action> {
        let mut ret: Vec<&dyn Action> = Vec::new();
        for z in &self.actions_runtime_pos {
            if z.name() == name {
                ret.push(z.as_ref());
            }
        }
        for z in &self.transformations {
            if z.name() == name {
                ret.push(z.as_ref());
            }
        }
        let ex = &t.rules.properties.exceptions;
        for z in ex.action_pre_update_target_by_id.for_id(self.rule_id as f64) {
            if z.name() == name {
                ret.push(z.as_ref());
            }
        }
        for z in ex.action_pos_update_target_by_id.for_id(self.rule_id as f64) {
            if z.name() == name {
                ret.push(z.as_ref());
            }
        }
        ret
    }

    /// `performLogging`
    pub fn perform_logging<'a>(
        &'a self,
        t: &mut Transaction<'a>,
        rm: &mut RuleMessage<'a>,
        last_log: bool,
        chained_parent_null: bool,
    ) {
        let mut is_it_to_be_logged = rm.save_message;
        if last_log {
            if chained_parent_null {
                is_it_to_be_logged = rm.save_message && !self.chained_rule_parent;
                if is_it_to_be_logged && !self.has_multimatch() {
                    t.rules_messages.push(rm.clone());
                    if !rm.is_disruptive {
                        t.server_log(rm);
                    }
                }
            } else if (self.has_block_action() && !self.has_multimatch())
                || (is_it_to_be_logged && !self.has_multimatch() && !rm.message.is_empty())
            {
                // (two C++ branches with identical bodies)
                t.rules_messages.push(rm.clone());
                if !rm.is_disruptive {
                    t.server_log(rm);
                }
            }
        } else if self.has_multimatch() && is_it_to_be_logged {
            t.rules_messages.push(rm.clone());
            if !rm.is_disruptive {
                t.server_log(rm);
            }
            rm.reset(false);
        }
    }
}
