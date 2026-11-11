//! Port of `src/variables/rule.cc`, `src/variables/rule.h`.
//!
//! `RULE:id`, `RULE:rev`, `RULE:severity`, `RULE:logdata` and `RULE:msg`:
//! properties of the rule being evaluated. Inside a chain, a property the
//! rule does not set is looked up in its chain parents. In C++ each rule
//! pointed at its parent (`m_chainedRuleParent`); here the ancestors of the
//! rule being evaluated are on `Transaction::chained_rule_parents`.

use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;
use crate::utils::regex::regex_search;
use crate::variable_origin::VariableOrigin;
use crate::variable_value::VariableValue;
use crate::variables::variable::{Variable, VariableBase, VariableDictElement, VariableRegex};

/// `Rule_DictElement::m_rule`
pub const RULE: &str = "RULE";
/// `Rule_DictElement::m_rule_id`
pub const RULE_ID: &str = "id";
/// `Rule_DictElement::m_rule_rev`
pub const RULE_REV: &str = "rev";
/// `Rule_DictElement::m_rule_severity`
pub const RULE_SEVERITY: &str = "severity";
/// `Rule_DictElement::m_rule_logdata`
pub const RULE_LOGDATA: &str = "logdata";
/// `Rule_DictElement::m_rule_msg`
pub const RULE_MSG: &str = "msg";

/// `r->m_chainedRuleParent`: the rule of the chain whose chained child is
/// `r`, if `r` is being evaluated as part of a chain.
fn chained_rule_parent<'r>(t: &'r Transaction<'_>, r: &RuleWithActions) -> Option<&'r RuleWithActions> {
    t.chained_rule_parents
        .iter()
        .rev()
        .find(|p| p.chained_rule_child.as_deref().is_some_and(|c| std::ptr::eq(c, r)))
        .copied()
}

/// Walks from `rule` up the chain parents and returns the first rule for
/// which `has` holds (the `while (r && !has(r)) r = r->m_chainedRuleParent`
/// loops of the C++ code).
fn find_in_chain<'r>(
    t: &'r Transaction<'_>,
    rule: Option<&'r RuleWithActions>,
    has: impl Fn(&RuleWithActions) -> bool,
) -> Option<&'r RuleWithActions> {
    let mut r = rule;
    while let Some(cur) = r {
        if has(cur) {
            return Some(cur);
        }
        r = chained_rule_parent(t, cur);
    }
    None
}

/// `Rule_DictElement::addVariableOrigin`
fn add_variable_origin(key: &str, value: &[u8], l: &mut Vec<VariableValue>) {
    let mut var = VariableValue::with_collection(RULE.as_bytes(), key.as_bytes(), value);
    var.add_origin(VariableOrigin::default());
    l.push(var);
}

/// `Rule_DictElement`
#[derive(Debug)]
pub struct RuleDictElement(pub VariableDictElement);

impl RuleDictElement {
    pub fn new(dict_element: &str) -> Self {
        RuleDictElement(VariableDictElement::new(RULE, dict_element))
    }

    /// `Rule_DictElement::id`
    pub fn id(t: &Transaction<'_>, rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        let Some(r) = find_in_chain(t, rule, |r| r.rule_id != 0) else {
            return;
        };
        add_variable_origin(RULE_ID, r.rule_id.to_string().as_bytes(), l);
    }

    /// `Rule_DictElement::rev`
    pub fn rev(t: &Transaction<'_>, rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        let Some(r) = find_in_chain(t, rule, |r| !r.rev.is_empty()) else {
            return;
        };
        add_variable_origin(RULE_REV, r.rev.as_bytes(), l);
    }

    /// `Rule_DictElement::severity`
    pub fn severity(t: &Transaction<'_>, rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        if let Some(r) = find_in_chain(t, rule, |r| r.has_severity()) {
            add_variable_origin(RULE_SEVERITY, r.severity().to_string().as_bytes(), l);
        }
    }

    /// `Rule_DictElement::logData`
    pub fn log_data(t: &Transaction<'_>, rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        if let Some(r) = find_in_chain(t, rule, |r| r.has_log_data()) {
            add_variable_origin(RULE_LOGDATA, &r.log_data(t), l);
        }
    }

    /// `Rule_DictElement::msg`
    pub fn msg(t: &Transaction<'_>, rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        if let Some(r) = find_in_chain(t, rule, |r| r.has_msg()) {
            add_variable_origin(RULE_MSG, &r.msg(t), l);
        }
    }
}

impl Variable for RuleDictElement {
    fn base(&self) -> &VariableBase {
        &self.0.base
    }
    fn base_mut(&mut self) -> &mut VariableBase {
        &mut self.0.base
    }
    fn evaluate(&self, t: &Transaction<'_>, rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        // The element is compared case sensitively, as in C++.
        let e = self.0.dict_element.as_str();
        if e == RULE_ID {
            Self::id(t, rule, l);
            return;
        }
        if rule.is_some() && e == RULE_REV {
            Self::rev(t, rule, l);
            return;
        }
        if rule.is_some() && e == RULE_SEVERITY {
            Self::severity(t, rule, l);
            return;
        }
        if e == RULE_LOGDATA {
            Self::log_data(t, rule, l);
            return;
        }
        if e == RULE_MSG {
            Self::msg(t, rule, l);
        }
    }
}

/// `Rule_DictElementRegexp`: the first property name the regex matches is
/// resolved.
#[derive(Debug)]
pub struct RuleDictElementRegexp(pub VariableRegex);

impl RuleDictElementRegexp {
    pub fn new(regex: &str) -> Self {
        RuleDictElementRegexp(VariableRegex::new(RULE, regex))
    }
}

impl Variable for RuleDictElementRegexp {
    fn base(&self) -> &VariableBase {
        &self.0.base
    }
    fn base_mut(&mut self) -> &mut VariableBase {
        &mut self.0.base
    }
    fn evaluate(&self, t: &Transaction<'_>, rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        let r = &self.0.r;
        if regex_search(RULE_ID.as_bytes(), r) > 0 {
            RuleDictElement::id(t, rule, l);
            return;
        }
        if regex_search(RULE_REV.as_bytes(), r) > 0 {
            RuleDictElement::rev(t, rule, l);
            return;
        }
        if regex_search(RULE_SEVERITY.as_bytes(), r) > 0 {
            RuleDictElement::severity(t, rule, l);
            return;
        }
        if regex_search(RULE_LOGDATA.as_bytes(), r) > 0 {
            RuleDictElement::log_data(t, rule, l);
            return;
        }
        if regex_search(RULE_MSG.as_bytes(), r) > 0 {
            RuleDictElement::msg(t, rule, l);
        }
    }
    fn regex(&self) -> Option<&crate::utils::regex::Regex> {
        Some(&self.0.r)
    }
}

/// `Rule_NoDictElement`: all the properties.
#[derive(Debug)]
pub struct RuleNoDictElement(pub VariableBase);

impl RuleNoDictElement {
    pub fn new() -> Self {
        RuleNoDictElement(VariableBase::new(RULE))
    }
}

impl Default for RuleNoDictElement {
    fn default() -> Self {
        Self::new()
    }
}

impl Variable for RuleNoDictElement {
    fn base(&self) -> &VariableBase {
        &self.0
    }
    fn base_mut(&mut self) -> &mut VariableBase {
        &mut self.0
    }
    fn evaluate(&self, t: &Transaction<'_>, rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        RuleDictElement::id(t, rule, l);
        RuleDictElement::rev(t, rule, l);
        RuleDictElement::severity(t, rule, l);
        RuleDictElement::log_data(t, rule, l);
        RuleDictElement::msg(t, rule, l);
    }
}
