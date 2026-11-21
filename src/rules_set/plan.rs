//! The plan of a rule set: what its rules do, worked out once.
//!
//! A rule alone does not say what runs. Its transformations depend on the
//! `SecDefaultAction` of its phase and on `SecRuleUpdateActionById`; its
//! targets on `SecRuleUpdateTargetById`, `...ByTag` and `...ByMsg`; and
//! `SecRuleRemoveById`, `...ByTag` and `...ByMsg` decide whether it runs
//! at all. All of these are directives of the rule set, so the answer is
//! the same for every transaction: [`Plan::compile`] works it out when
//! the rule set is first used (see [`RulesSet::plan`]) and the evaluation
//! follows the plan.
//!
//! What a transaction changes while it runs (`ctl:ruleRemoveById`,
//! `ctl:ruleRemoveTargetById`, ...) is still looked at during the
//! evaluation.

use std::sync::Arc;

use crate::actions::action::{Action, Kind};
use crate::actions::rule_action::RuleAction;
use crate::actions::transformation::Transformation;
use crate::phases::{NUMBER_OF_PHASES, Phases};
use crate::rule::Rule;
use crate::rules_set::RulesSet;
use crate::rules_set::entry::Entry;
use crate::variables::variable::Variable;
use crate::variables::variable_value::VariableValue;
use modsecurity_types::key_exclusions::same_name;

/// The plan of a rule set: the steps of each phase, in order.
#[derive(Debug)]
pub(crate) struct Plan {
    phases: [Vec<Step>; NUMBER_OF_PHASES + 1],
}

/// An entry of a phase.
#[derive(Debug)]
pub(crate) enum Step {
    /// A `SecMarker`.
    Marker(Arc<Entry>),
    /// A rule that runs, with the plan of each rule of its chain (itself
    /// first).
    Rule { rule: Arc<Entry>, chain: Vec<Link> },
    /// A rule that a directive removed. It keeps its place: `skip` counts
    /// it.
    Removed { rule: Arc<Entry>, by: RemovedBy },
}

/// The directive that removed a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemovedBy {
    Id,
    Msg,
    Tag,
}

impl RemovedBy {
    /// The directive, as the debug log names it.
    pub(crate) fn directive(self) -> &'static str {
        match self {
            RemovedBy::Id => "an SecRuleRemove",
            RemovedBy::Msg => "a SecRuleRemoveByMsg",
            RemovedBy::Tag => "a SecRuleRemoveByTag",
        }
    }
}

/// What one rule of a chain does in its rule set.
#[derive(Debug, Default)]
pub struct Link {
    /// The transformations applied to each value, in order: the ones of
    /// `SecDefaultAction` (unless the rule has a `t:none`), the rule's
    /// own after its last `t:none`, then the ones of
    /// `SecRuleUpdateActionById` (likewise).
    pub(crate) transformations: Vec<Transformation>,
    /// Their names, joined with `,`.
    pub(crate) transformation_path: String,
    /// The rule's own targets that no `SecRuleUpdateTarget...` excludes:
    /// positions in the variables of the `SecRule`.
    pub(crate) targets: Vec<usize>,
    /// The targets that `SecRuleUpdateTarget...` directives add.
    pub(crate) added_targets: Vec<Arc<Variable>>,
    /// The `!TARGET`s of `SecRuleUpdateTarget...` directives.
    excluded_targets: Vec<Arc<Variable>>,
    /// The actions of the phase's `SecDefaultAction` that run when the
    /// rule matches: all but the disruptive one.
    pub(crate) default_actions: Vec<Arc<RuleAction>>,
    /// What `block` does: the disruptive action of the phase's
    /// `SecDefaultAction`.
    pub(crate) block_actions: Vec<Arc<RuleAction>>,
    /// The actions that `SecRuleUpdateActionById` adds to the rule.
    pub(crate) update_actions: Vec<Arc<RuleAction>>,
}

impl Plan {
    pub(crate) fn compile(rules: &RulesSet) -> Plan {
        let phases = std::array::from_fn(|phase| {
            rules.rules_set_phases.at_index(phase).iter().map(|entry| Step::compile(entry, rules)).collect()
        });
        Plan { phases }
    }

    pub(crate) fn for_phase(&self, phase: Phases) -> &[Step] {
        &self.phases[phase.index()]
    }
}

impl Step {
    fn compile(entry: &Arc<Entry>, rules: &RulesSet) -> Step {
        let Some(rule) = entry.as_rule() else {
            return Step::Marker(entry.clone());
        };
        let ex = &rules.properties.exceptions;
        let by = if ex.contains(rule.rule_id) {
            Some(RemovedBy::Id)
        } else if ex.remove_rule_by_msg.iter().any(|msg| rule.msg_is(msg)) {
            Some(RemovedBy::Msg)
        } else if ex.remove_rule_by_tag.iter().any(|tag| rule.has_tag(tag)) {
            Some(RemovedBy::Tag)
        } else {
            None
        };
        if let Some(by) = by {
            return Step::Removed { rule: entry.clone(), by };
        }
        let chain = std::iter::successors(Some(rule), |r| r.chained_rule_child.as_deref())
            .map(|r| Link::compile(r, rules))
            .collect();
        Step::Rule { rule: entry.clone(), chain }
    }
}

impl Link {
    pub(crate) fn compile(rule: &Rule, rules: &RulesSet) -> Link {
        let transformations = Self::transformations(rule, rules);
        let transformation_path = transformations.iter().map(Transformation::name).collect::<Vec<_>>().join(",");

        // SecRuleUpdateTargetByTag, ...ByMsg and ...ById, in this order:
        // a `!TARGET` excludes, anything else is added.
        let ex = &rules.properties.exceptions;
        let by_tag = ex.variable_update_target_by_tag.iter().filter(|(tag, _)| rule.has_tag(tag)).map(|(_, v)| v);
        let by_msg = ex.variable_update_target_by_msg.iter().filter(|(msg, _)| rule.msg_is(msg)).map(|(_, v)| v);
        let by_id = ex.variable_update_target_by_id.for_rule(rule.rule_id).iter();
        let (excluded_targets, added_targets): (Vec<_>, Vec<_>) =
            by_tag.chain(by_msg).chain(by_id).cloned().partition(|v| v.exclusion_base().is_some());

        let own = rule.as_sec_rule().map_or(&[][..], |r| &r.variables);
        let excluded = |v: &Variable| excluded_targets.iter().filter_map(|e| e.exclusion_base()).any(|e| v.same_as(e));
        let targets = (0..own.len()).filter(|&i| !excluded(&own[i])).collect();

        let defaults = &rules.properties.default_actions[rule.phase().index()];
        let on_match = defaults.iter().filter(|a| a.kind() == Kind::RunTimeOnlyIfMatch);
        let (block_actions, default_actions) = on_match.cloned().partition(|a| a.is_disruptive());
        let update_actions = ex.action_pos_update_target_by_id.for_rule(rule.rule_id).to_vec();

        Link {
            transformations,
            transformation_path,
            targets,
            added_targets,
            excluded_targets,
            default_actions,
            block_actions,
            update_actions,
        }
    }

    fn transformations(rule: &Rule, rules: &RulesSet) -> Vec<Transformation> {
        let mut list = Vec::new();
        let own = rule.transformations();

        // The ones of SecDefaultAction, unless the rule has a `t:none`.
        if !own.iter().any(Transformation::is_none) {
            let defaults = &rules.properties.default_actions[rule.phase().index()];
            list.extend(
                defaults
                    .iter()
                    .filter(|a| a.kind() == Kind::RunTimeBeforeMatchAttempt)
                    .filter_map(|a| a.as_transformation())
                    .cloned(),
            );
        }

        // The rule's own, then the ones of SecRuleUpdateActionById: of
        // each list, what follows its last `t:none`.
        let after_last_none = |all: Vec<&Transformation>| {
            let start = all.iter().rposition(|t| t.is_none()).map_or(0, |i| i + 1);
            all.into_iter().skip(start).cloned().collect::<Vec<_>>()
        };
        list.extend(after_last_none(own.iter().collect()));
        let updates = rules.properties.exceptions.action_pre_update_target_by_id.for_rule(rule.rule_id);
        list.extend(after_last_none(updates.iter().filter_map(|a| a.as_transformation()).collect()));
        list
    }

    /// Whether a `!TARGET` of a `SecRuleUpdateTarget...` directive
    /// excludes the value `v`: by regex for `COLLECTION:/regex/`, by full
    /// name otherwise (ignoring case, see [`same_name`]).
    pub(crate) fn excludes_value(&self, v: &VariableValue) -> bool {
        self.excluded_targets.iter().filter_map(|e| e.exclusion_base()).any(|e| match e.regex() {
            Some(r) => r.is_match(v.key()),
            None => same_name(v.key_with_collection(), e.full_name().as_bytes()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(conf: &str) -> RulesSet {
        let mut rules = RulesSet::new();
        rules.load(conf).unwrap();
        rules
    }

    /// The plan of the rules of phase 1: `removed` or the transformation
    /// path and the targets of each rule of the chain.
    fn phase1(rules: &RulesSet) -> Vec<String> {
        let describe = |rule: &Rule, link: &Link| {
            let own = rule.as_sec_rule().map_or(&[][..], |r| &r.variables);
            let targets = link.targets.iter().map(|&i| own[i].full_name());
            let added = link.added_targets.iter().map(|v| v.full_name());
            format!("[{}] {}", link.transformation_path, targets.chain(added).collect::<Vec<_>>().join("|"))
        };
        rules
            .plan()
            .for_phase(Phases::RequestHeaders)
            .iter()
            .map(|step| match step {
                Step::Marker(_) => "marker".to_string(),
                Step::Removed { by, .. } => format!("removed by {}", by.directive()),
                Step::Rule { rule, chain } => {
                    let links = std::iter::successors(rule.as_rule(), |r| r.chained_rule_child.as_deref());
                    links.zip(chain).map(|(r, l)| describe(r, l)).collect::<Vec<_>>().join(" -> ")
                }
            })
            .collect()
    }

    #[test]
    fn transformations() {
        let plan = phase1(&rules(
            r#"
            SecDefaultAction "phase:1,pass,t:lowercase"
            SecRule ARGS "@rx x" "id:1,phase:1,pass,t:trim"
            SecRule ARGS "@rx x" "id:2,phase:1,pass,t:trim,t:none,t:urlDecode,t:length"
            SecRule ARGS "@rx x" "id:3,phase:1,pass,t:trim,chain"
                SecRule ARGS "@rx x" "t:none,t:hexEncode"
            SecRuleUpdateActionById 1 "t:none,t:sha1"
            "#,
        ));
        assert_eq!(
            plan,
            [
                // The default, the rule's own, then the update's after its t:none.
                "[t:lowercase,t:trim,t:sha1] ARGS",
                // A t:none drops the default and what precedes it.
                "[t:urlDecode,t:length] ARGS",
                "[t:lowercase,t:trim] ARGS -> [t:hexEncode] ARGS",
            ]
        );
    }

    #[test]
    fn targets() {
        let plan = phase1(&rules(
            r#"
            SecRule ARGS|REQUEST_COOKIES|ARGS_NAMES "@rx x" "id:1,phase:1,pass,tag:'a',msg:'m'"
            SecRule ARGS|REQUEST_COOKIES "@rx x" "id:2,phase:1,pass,tag:'b'"
            SecRuleUpdateTargetById 1 "!REQUEST_COOKIES"
            SecRuleUpdateTargetById 1 "!ARGS:skipped"
            SecRuleUpdateTargetByTag a "REQUEST_URI"
            SecRuleUpdateTargetByMsg m "!ARGS_NAMES"
            SecRuleUpdateTargetByTag b "XML:/*"
            "#,
        ));
        // `!ARGS:skipped` leaves ARGS in the list: it excludes a value.
        assert_eq!(plan, ["[] ARGS|REQUEST_URI", "[] ARGS|REQUEST_COOKIES|XML:/*"]);
    }

    #[test]
    fn removed_rules_keep_their_place() {
        let conf = r#"
            SecRule ARGS "@rx x" "id:1,phase:1,pass,tag:'t'"
            SecMarker HERE
            SecRule ARGS "@rx x" "id:2,phase:1,pass,msg:'m'"
            SecRule ARGS "@rx x" "id:3,phase:1,pass"
            SecAction "id:4,phase:1,pass"
            SecRuleRemoveByTag t
            SecRuleRemoveByMsg m
            SecRuleRemoveById 3
        "#;
        assert_eq!(
            phase1(&rules(conf)),
            [
                "removed by a SecRuleRemoveByTag",
                "marker",
                "removed by a SecRuleRemoveByMsg",
                "removed by an SecRuleRemove",
                "[] ",
            ]
        );
    }

    /// The directives are matched with tags and messages as written: a
    /// macro in them expands to nothing. (They used to be expanded for
    /// each transaction, as in C++.)
    #[test]
    fn tags_and_messages_are_matched_as_written() {
        let conf = r#"
            SecAction "id:1,phase:1,pass,setvar:tx.kind=attack"
            SecRule ARGS "@rx x" "id:2,phase:1,pass,tag:'%{tx.kind}-sqli'"
            SecRule ARGS "@rx x" "id:3,phase:1,pass,tag:'%{tx.kind}-xss'"
            SecRuleRemoveByTag attack-sqli
            SecRuleRemoveByTag -xss
        "#;
        assert_eq!(phase1(&rules(conf)), ["[] ", "[] ARGS", "removed by a SecRuleRemoveByTag"]);
    }

    #[test]
    fn actions_of_the_rule_set() {
        let rules = rules(
            r#"
            SecDefaultAction "phase:1,log,auditlog,deny,status:403,t:lowercase"
            SecRule ARGS "@rx x" "id:1,phase:1,block"
            SecRule ARGS "@rx x" "id:2,phase:2,block"
            SecRuleUpdateActionById 1 "pass,tag:'updated',t:trim"
            "#,
        );
        let names = |list: &[Arc<RuleAction>]| list.iter().map(|a| a.name().to_string()).collect::<Vec<_>>();
        let link = |phase| match &rules.plan().for_phase(phase)[0] {
            Step::Rule { chain, .. } => &chain[0],
            _ => panic!("a rule"),
        };
        let one = link(Phases::RequestHeaders);
        assert_eq!(names(&one.default_actions), ["log", "auditlog", "status"]);
        assert_eq!(names(&one.block_actions), ["deny"]);
        // The transformation is with the transformations.
        assert_eq!(names(&one.update_actions), ["pass", "tag"]);
        assert_eq!(one.transformation_path, "t:lowercase,t:trim");
        // Phase 2 has no SecDefaultAction.
        let two = link(Phases::RequestBody);
        assert!(two.default_actions.is_empty() && two.block_actions.is_empty() && two.update_actions.is_empty());
    }

    /// `SecRuleUpdateActionById` replaces the rule's disruptive action
    /// only with another one. (In C++ any action it adds, a `tag` for
    /// instance, switches the rule's disruptive action off.)
    #[test]
    fn an_update_replaces_the_disruptive_action_only_with_another() {
        let status = |update: &str| {
            let rules = rules(&format!(
                "SecRuleEngine On\nSecRule REQUEST_URI \"@contains x\" \"id:1,phase:1,deny,status:403\"\n{update}"
            ));
            let ms = crate::ModSecurity::new();
            let mut t = crate::Transaction::new(&ms, &rules, None);
            t.process_uri(b"/x", b"GET", b"1.1");
            t.process_request_headers();
            t.intervention().map(|it| it.status)
        };
        assert_eq!(status(""), Some(403));
        assert_eq!(status("SecRuleUpdateActionById 1 \"tag:'extra'\""), Some(403));
        assert_eq!(status("SecRuleUpdateActionById 1 \"setvar:tx.seen=1,logdata:'x'\""), Some(403));
        assert_eq!(status("SecRuleUpdateActionById 1 \"pass\""), None);
    }

    /// Every way of removing a target by its name compares names ignoring
    /// case. (`SecRuleUpdateTargetById` and `ctl:ruleRemoveTargetBy...`
    /// compared the value's name exactly: `?Password=x` escaped a removal
    /// of `ARGS:password`.)
    #[test]
    fn target_removals_ignore_case() {
        let status = |removal: &str, query: &str| {
            let rule = "SecRule ARGS{} \"@rx x\" \"id:1,phase:1,deny,status:403,tag:'t'\"";
            let conf = match removal.strip_prefix('|') {
                Some(excluded) => format!("SecRuleEngine On\n{}", rule.replace("{}", &format!("|{excluded}"))),
                None => format!("SecRuleEngine On\n{removal}\n{}", rule.replace("{}", "")),
            };
            let rules = rules(&conf);
            let ms = crate::ModSecurity::new();
            let mut t = crate::Transaction::new(&ms, &rules, None);
            t.process_uri(format!("/?{query}=x").as_bytes(), b"GET", b"1.1");
            t.process_request_headers();
            t.intervention().map(|it| it.status)
        };
        for removal in [
            "|!ARGS:password",
            "SecRuleUpdateTargetById 1 \"!ARGS:password\"",
            "SecRuleUpdateTargetByTag t \"!args:PASSWORD\"",
            "SecAction \"id:2,phase:1,pass,nolog,ctl:ruleRemoveTargetById=1;ARGS:password\"",
            "SecAction \"id:2,phase:1,pass,nolog,ctl:ruleRemoveTargetByTag=t;args:password\"",
        ] {
            assert_eq!(status(removal, "Password"), None, "{removal}");
            assert_eq!(status(removal, "PASSWORD"), None, "{removal}");
            assert_eq!(status(removal, "other"), Some(403), "{removal}");
        }
    }

    #[test]
    fn a_new_load_makes_a_new_plan() {
        let mut rules = rules(r#"SecRule ARGS "@rx x" "id:1,phase:1,pass""#);
        assert_eq!(phase1(&rules), ["[] ARGS"]);
        rules.load("SecRuleRemoveById 1\nSecRule ARGS \"@rx x\" \"id:2,phase:1,pass,t:trim\"").unwrap();
        assert_eq!(phase1(&rules), ["removed by an SecRuleRemove", "[t:trim] ARGS"]);
    }
}
