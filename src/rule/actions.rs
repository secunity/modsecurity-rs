//! The run time actions of a rule, in the order they run (`crate::eval`
//! runs them).
//!
//! A rule has two moments for its actions. On every match of its operator
//! the `setvar`s run, whatever becomes of the chain. Once the whole chain
//! matched, the other actions run in a fixed order: the `tag`s,
//! `severity`, `logdata`, `msg`, the remaining actions as written, and
//! last the disruptive action. [`Actions`] keeps them in that order; what
//! the rule set adds (`SecDefaultAction`, `SecRuleUpdateActionById`) comes
//! from the rule's [`Link`](crate::rules_set::plan::Link).

use crate::actions::log_data::LogData;
use crate::actions::msg::Msg;
use crate::actions::rule_action::RuleAction;
use crate::actions::set_var::SetVar;
use crate::actions::severity::Severity;
use crate::actions::tag::Tag;

/// The run time actions of a rule.
#[derive(Debug, Default)]
pub struct Actions {
    /// Run on every match of the operator.
    set_vars: Vec<SetVar>,
    /// Run once the chain matched, in the order they run: see [`stage`].
    on_match: Vec<RuleAction>,
    /// How many of `on_match` are tags (they come first).
    tags: usize,
}

/// Where an action runs among those of a matched chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Stage {
    Tag,
    Severity,
    LogData,
    Msg,
    Other,
    Disruptive,
}

/// The stage of `a`.
pub(crate) fn stage(a: &RuleAction) -> Stage {
    match a {
        RuleAction::Tag(_) => Stage::Tag,
        RuleAction::Severity(_) => Stage::Severity,
        RuleAction::LogData(_) => Stage::LogData,
        RuleAction::Msg(_) => Stage::Msg,
        a if a.is_disruptive() => Stage::Disruptive,
        _ => Stage::Other,
    }
}

impl Actions {
    /// Adds a run time action. A rule has one `severity`, `logdata`, `msg`
    /// and disruptive action: a later one replaces the earlier.
    pub(super) fn add(&mut self, a: RuleAction) {
        let a = match a {
            RuleAction::SetVar(s) => return self.set_vars.push(s),
            a => a,
        };
        let at = stage(&a);
        if !matches!(at, Stage::Tag | Stage::Other) {
            self.on_match.retain(|b| stage(b) != at);
        }
        // After the actions of its stage and of the ones before it.
        let place = self.on_match.iter().position(|b| stage(b) > at).unwrap_or(self.on_match.len());
        self.on_match.insert(place, a);
        self.tags += usize::from(at == Stage::Tag);
    }

    pub fn set_vars(&self) -> &[SetVar] {
        &self.set_vars
    }

    pub fn tags(&self) -> impl Iterator<Item = &Tag> {
        self.on_match[..self.tags].iter().filter_map(|a| match a {
            RuleAction::Tag(tag) => Some(tag),
            _ => None,
        })
    }

    /// The actions that run once the chain matched, after the tags.
    pub fn after_tags(&self) -> &[RuleAction] {
        &self.on_match[self.tags..]
    }

    pub fn severity(&self) -> Option<&Severity> {
        self.after_tags().iter().find_map(|a| match a {
            RuleAction::Severity(s) => Some(s),
            _ => None,
        })
    }

    pub fn log_data(&self) -> Option<&LogData> {
        self.after_tags().iter().find_map(|a| match a {
            RuleAction::LogData(l) => Some(l),
            _ => None,
        })
    }

    pub fn msg(&self) -> Option<&Msg> {
        self.after_tags().iter().find_map(|a| match a {
            RuleAction::Msg(m) => Some(m),
            _ => None,
        })
    }

    /// The disruptive action (`deny`, `pass`, ...): the last one.
    pub fn disruptive(&self) -> Option<&RuleAction> {
        self.on_match.last().filter(|a| a.is_disruptive())
    }
}

#[cfg(test)]
mod tests {
    use crate::rules_set::RulesSet;

    /// The actions of the first rule of `conf`, as they run on a match.
    fn on_match(conf: &str) -> (Vec<String>, Vec<String>) {
        let mut rules = RulesSet::new();
        rules.load(conf).unwrap();
        let entry = &rules.rules_set_phases.for_phase(crate::phases::Phases::RequestHeaders)[0];
        let actions = entry.as_rule().unwrap().actions();
        let tags = actions.tags().map(|t| crate::actions::action::Action::name(t).to_string());
        let rest = actions.after_tags().iter().map(|a| a.name().to_string());
        (actions.set_vars().iter().map(|_| "setvar".to_string()).collect(), tags.chain(rest).collect())
    }

    #[test]
    fn order() {
        let (each_match, chain_matched) = on_match(
            "SecRule ARGS \"@rx x\" \"id:1,phase:1,deny,status:403,msg:'m',setvar:tx.a=1,ctl:ruleEngine=Off,\\
             tag:'t1',logdata:'d',capture,severity:2,tag:'t2',setvar:tx.b=2,skip:1,t:none\"",
        );
        assert_eq!(each_match, ["setvar", "setvar"]);
        // Tags, severity, logdata, msg, the others as written, the
        // disruptive action.
        assert_eq!(chain_matched, ["tag", "tag", "severity", "logdata", "msg", "status", "ctl", "skip", "deny"]);
    }

    /// A rule has one severity, logdata, msg and disruptive action.
    #[test]
    fn the_last_one_counts() {
        let mut rules = RulesSet::new();
        rules
            .load("SecRule ARGS \"@rx x\" \"id:1,phase:1,deny,msg:'first',severity:2,pass,msg:'second',severity:5\"")
            .unwrap();
        let entry = &rules.rules_set_phases.for_phase(crate::phases::Phases::RequestHeaders)[0];
        let rule = entry.as_rule().unwrap();
        let actions = rule.actions();
        assert_eq!(actions.after_tags().len(), 3);
        assert_eq!(rule.severity(), Some(5));
        assert_eq!(*actions.msg().unwrap().string.text(), *b"second");
        assert_eq!(actions.disruptive().unwrap().name(), "pass");
    }
}
