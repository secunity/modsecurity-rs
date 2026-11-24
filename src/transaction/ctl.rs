//! What `ctl:` actions changed for one transaction: settings that take the
//! place of the rule set's, and the rules and targets they removed.

use std::ops::RangeInclusive;

use super::Transaction;
use crate::audit_log::{AuditLogStatus, Parts, PartsChange};
use crate::rule::{Id, Rule};
use crate::rules_set::RulesSet;
use crate::rules_set::properties::{ParseXmlIntoArgs, RuleEngine};
use modsecurity_types::key_exclusions::same_name;

/// The settings rules changed for this transaction with `ctl:` (`None`:
/// the rule set's value applies), and the removals they asked for.
pub(crate) struct CtlOverrides {
    /// `ctl:ruleEngine`.
    pub(crate) rule_engine: Option<RuleEngine>,
    /// `ctl:requestBodyAccess`.
    pub(crate) request_body_access: Option<bool>,
    /// `ctl:parseXmlIntoArgs` (starts as the rule set's value).
    pub(crate) parse_xml_into_args: Option<ParseXmlIntoArgs>,
    /// `ctl:auditEngine`.
    pub(crate) audit_engine: Option<AuditLogStatus>,
    /// `ctl:auditLogParts` changes, in rule order.
    pub(crate) audit_log_modifier: Vec<(PartsChange, Parts)>,
    /// `ctl:ruleRemoveById`: ranges of ids (of one id for a single one).
    pub(crate) rule_remove_by_id: Vec<RangeInclusive<Id>>,
    /// `ctl:ruleRemoveByTag`: the tags.
    pub(crate) rule_remove_by_tag: Vec<String>,
    /// `ctl:ruleRemoveTargetByTag`: (tag, target).
    pub(crate) rule_remove_target_by_tag: Vec<(String, String)>,
    /// `ctl:ruleRemoveTargetById`: (id, target).
    pub(crate) rule_remove_target_by_id: Vec<(Id, String)>,
}

impl CtlOverrides {
    /// Nothing changed yet.
    pub(crate) fn new(rules: &RulesSet) -> Self {
        CtlOverrides {
            rule_engine: None,
            request_body_access: None,
            parse_xml_into_args: rules.properties.settings.sec_xml_parse_xml_into_args,
            audit_engine: None,
            audit_log_modifier: Vec::new(),
            rule_remove_by_id: Vec::new(),
            rule_remove_by_tag: Vec::new(),
            rule_remove_target_by_tag: Vec::new(),
            rule_remove_target_by_id: Vec::new(),
        }
    }

    /// Whether `ctl:ruleRemoveById` removed the rule with this id.
    pub(crate) fn removes_rule_id(&self, id: Option<Id>) -> bool {
        id.is_some_and(|id| self.rule_remove_by_id.iter().any(|ids| ids.contains(&id)))
    }

    /// Whether `ctl:ruleRemoveByTag` removed `rule`: one of its tags
    /// expands, in `t`, to a removed tag.
    pub(crate) fn removes_rule_by_tag(&self, rule: &Rule, t: &Transaction<'_>) -> bool {
        self.rule_remove_by_tag.iter().any(|tag| rule.contains_tag(tag, t))
    }

    /// Whether `ctl:ruleRemoveTargetById` or `...ByTag` removed the target
    /// `name` (`ARGS:foo`) from `rule`. Names are compared ignoring case
    /// ([`same_name`]).
    pub(crate) fn removes_target(&self, rule: &Rule, name: &[u8], t: &Transaction<'_>) -> bool {
        self.rule_remove_target_by_id
            .iter()
            .any(|(id, target)| rule.rule_id == Some(*id) && same_name(target.as_bytes(), name))
            || self
                .rule_remove_target_by_tag
                .iter()
                .any(|(tag, target)| same_name(target.as_bytes(), name) && rule.contains_tag(tag, t))
    }
}

#[cfg(test)]
mod tests {
    use crate::instance::ModSecurity;
    use crate::rules_set::RulesSet;
    use crate::transaction::Transaction;

    /// The status a request for `uri` gets when rule 10 runs `ctl:{ctl}`
    /// before rule 20, which denies any argument. Rule 20's tag is
    /// `attack-sqli` once expanded.
    fn status(ctl: &str, uri: &[u8]) -> Option<u16> {
        let ms = ModSecurity::new();
        let mut rules = RulesSet::new();
        rules
            .load(&format!(
                "SecRuleEngine On\n\
                 SecAction \"id:5,phase:1,pass,nolog,setvar:tx.kind=sqli\"\n\
                 SecAction \"id:10,phase:1,pass,nolog,ctl:{ctl}\"\n\
                 SecRule ARGS \"@rx .\" \"id:20,phase:1,deny,status:403,tag:'attack-%{{tx.kind}}'\"\n"
            ))
            .unwrap();
        let mut t = Transaction::new(&ms, &rules, None);
        t.process_uri(uri, b"GET", b"1.1");
        t.process_request_headers();
        t.intervention().map(|i| i.status)
    }

    #[test]
    fn removals() {
        assert_eq!(status("ruleRemoveById=21", b"/?a=1"), Some(403));
        assert_eq!(status("ruleRemoveById=15-25", b"/?a=1"), None);
        // The tag as it expands in the transaction.
        assert_eq!(status("ruleRemoveByTag=attack-sqli", b"/?a=1"), None);
        assert_eq!(status("ruleRemoveByTag=attack-xss", b"/?a=1"), Some(403));
        // A target name, ignoring case; the other arguments stay.
        assert_eq!(status("ruleRemoveTargetById=20;args:A", b"/?a=1"), None);
        assert_eq!(status("ruleRemoveTargetById=20;ARGS:a", b"/?a=1&b=2"), Some(403));
        assert_eq!(status("ruleRemoveTargetById=21;ARGS:a", b"/?a=1"), Some(403));
        assert_eq!(status("ruleRemoveTargetByTag=attack-sqli;ARGS:a", b"/?a=1"), None);
        assert_eq!(status("ruleRemoveTargetByTag=attack-xss;ARGS:a", b"/?a=1"), Some(403));
    }
}
