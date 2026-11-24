//! A rule: `SecRule`, `SecAction` or `SecRuleScript`, with its actions and
//! transformations, as the configuration gave it (`crate::eval` runs it).
//!
//! What the three have in common is [`Rule`]; what differs is its
//! [`RuleKind`]. The first rule of a chain owns the next one
//! ([`Chain::next`]); a rule is not linked back to the one before it
//! ([`Chain::is_continuation`] says there is one), and the transaction keeps
//! the stack of chain ancestors during evaluation (the `RULE` variable walks
//! it).

mod actions;
pub mod id;
pub mod message;
pub mod sec_rule;
pub mod sec_rule_script;

pub use actions::Actions;
pub(crate) use actions::{Stage, stage};
pub use id::Id;

use crate::actions::action::{Action, Kind};
use crate::actions::rule_action::RuleAction;
use crate::actions::transformation::Transformation;
use crate::phases::Phases;
use crate::rule::sec_rule::SecRule;
use crate::rule::sec_rule_script::Script;
use crate::transaction::Transaction;

/// A transformed value and the transformation path that produced it
/// (e.g. `t:lowercase,t:urlDecode`).
pub type TransformationResult = (Vec<u8>, TransformationPath);

/// The transformation path of a [`TransformationResult`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransformationPath {
    /// With `multiMatch`: the original value (empty path) or the one
    /// transformation that produced this value.
    Step(String),
    /// All the transformations of the rule (the `transformation_path` of
    /// its `Link`).
    Full,
}
pub type TransformationResults = Vec<TransformationResult>;

/// Where a rule's message is logged from (`crate::eval`), which decides
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

/// What a rule says about itself, for the logs.
#[derive(Debug, Default)]
pub struct Metadata {
    /// `rev`.
    pub rev: String,
    /// `ver`.
    pub ver: String,
    /// `accuracy`.
    pub accuracy: u8,
    /// `maturity`.
    pub maturity: u8,
}

/// A rule's place in a chain. With the `chain` action, the rule that comes
/// next in the configuration continues it; the first rule of a chain owns
/// the others.
#[derive(Debug, Default)]
pub struct Chain {
    /// The rule has the `chain` action.
    pub continued: bool,
    /// The rule that continues it: `None` until the parser reads it, and
    /// for good when the configuration ends first (the chain then does not
    /// match).
    pub next: Option<Box<Rule>>,
    /// The rule continues another one (it is not the first of its chain).
    pub is_continuation: bool,
}

/// A rule of a configuration.
#[derive(Debug)]
pub struct Rule {
    /// Where the rule was read.
    pub file_name: String,
    pub line_number: usize,
    phase: Phases,
    /// `id:N`: every `SecRule` that starts a chain has one.
    pub rule_id: Option<Id>,
    pub metadata: Metadata,
    pub chain: Chain,

    actions: Actions,
    transformations: Vec<Transformation>,

    // Actions that are not kept, only recorded.
    contains_capture_action: bool,
    contains_multi_match_action: bool,
    contains_static_block_action: bool,

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
            rule_id: None,
            metadata: Metadata::default(),
            chain: Chain::default(),
            actions: Actions::default(),
            transformations: transformations.unwrap_or_default(),
            contains_capture_action: false,
            contains_multi_match_action: false,
            contains_static_block_action: false,
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

    /// The id as the logs write it: 0 for a rule without one.
    pub fn logged_id(&self) -> Id {
        self.rule_id.unwrap_or(0)
    }

    /// The rule id for `SecRule`s, `file:line` otherwise.
    pub fn reference(&self) -> String {
        match self.kind {
            RuleKind::SecRule(_) => self.logged_id().to_string(),
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

    pub fn has_capture_action(&self) -> bool {
        self.contains_capture_action
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

    /// The `severity` of the rule.
    pub fn severity(&self) -> Option<u8> {
        self.actions.severity().map(|s| s.severity)
    }

    pub fn transformations(&self) -> &[Transformation] {
        &self.transformations
    }

    /// The run time actions of the rule.
    pub fn actions(&self) -> &Actions {
        &self.actions
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
}
