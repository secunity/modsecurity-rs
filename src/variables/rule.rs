//! The `RULE` variable (`RULE:id`, `RULE:rev`, `RULE:severity`,
//! `RULE:logdata` and `RULE:msg`): properties of the rule being evaluated.
//! Inside a chain, a property the rule does not set is looked up in its
//! chain parents. A rule has no pointer to its parent:
//! the ancestors of the rule being evaluated
//! are in the transaction (`eval.chained_rule_parents`).

use crate::rule::Rule;
use crate::transaction::Transaction;
use crate::variables::variable::Selector;
use crate::variables::variable_origin::VariableOrigin;
use crate::variables::variable_value::VariableValue;

/// The collection name of the `RULE` variable.
pub const RULE: &str = "RULE";
/// The key of `RULE:id`.
pub const RULE_ID: &str = "id";
/// The key of `RULE:rev`.
pub const RULE_REV: &str = "rev";
/// The key of `RULE:severity`.
pub const RULE_SEVERITY: &str = "severity";
/// The key of `RULE:logdata`.
pub const RULE_LOGDATA: &str = "logdata";
/// The key of `RULE:msg`.
pub const RULE_MSG: &str = "msg";

/// The rule of the chain whose chained child is `r`, if `r` is being
/// evaluated as part of a chain.
fn chained_rule_parent<'r>(t: &'r Transaction<'_>, r: &Rule) -> Option<&'r Rule> {
    t.eval
        .chained_rule_parents
        .iter()
        .rev()
        .find(|p| p.chained_rule_child.as_deref().is_some_and(|c| std::ptr::eq(c, r)))
        .copied()
}

/// Walks from `rule` up the chain parents and returns the first rule for
/// which `has` holds.
fn find_in_chain<'r>(t: &'r Transaction<'_>, rule: Option<&'r Rule>, has: impl Fn(&Rule) -> bool) -> Option<&'r Rule> {
    let mut r = rule;
    while let Some(cur) = r {
        if has(cur) {
            return Some(cur);
        }
        r = chained_rule_parent(t, cur);
    }
    None
}

/// Appends the value of `RULE:key`, with an empty origin, to `l`.
fn add_variable_origin(key: &str, value: &[u8], l: &mut Vec<VariableValue>) {
    let mut var = VariableValue::with_collection(RULE.as_bytes(), key.as_bytes(), value);
    var.add_origin(VariableOrigin::default());
    l.push(var);
}

/// `RULE:id`: the id of the rule or of the nearest chain parent with one.
fn id(t: &Transaction<'_>, rule: Option<&Rule>, l: &mut Vec<VariableValue>) {
    let Some(r) = find_in_chain(t, rule, |r| r.rule_id.get() != 0) else {
        return;
    };
    add_variable_origin(RULE_ID, r.rule_id.to_string().as_bytes(), l);
}

/// `RULE:rev`: the revision of the rule or of the nearest chain parent
/// with one.
fn rev(t: &Transaction<'_>, rule: Option<&Rule>, l: &mut Vec<VariableValue>) {
    let Some(r) = find_in_chain(t, rule, |r| !r.rev.is_empty()) else {
        return;
    };
    add_variable_origin(RULE_REV, r.rev.as_bytes(), l);
}

/// `RULE:severity`: the severity of the rule or of the nearest chain
/// parent with one.
fn severity(t: &Transaction<'_>, rule: Option<&Rule>, l: &mut Vec<VariableValue>) {
    if let Some(r) = find_in_chain(t, rule, |r| r.has_severity()) {
        add_variable_origin(RULE_SEVERITY, r.severity().to_string().as_bytes(), l);
    }
}

/// `RULE:logdata`: the expanded `logdata` of the rule or of the nearest
/// chain parent with one.
fn log_data(t: &Transaction<'_>, rule: Option<&Rule>, l: &mut Vec<VariableValue>) {
    if let Some(r) = find_in_chain(t, rule, |r| r.has_log_data()) {
        add_variable_origin(RULE_LOGDATA, &r.log_data(t), l);
    }
}

/// `RULE:msg`: the expanded `msg` of the rule or of the nearest chain
/// parent with one.
fn msg(t: &Transaction<'_>, rule: Option<&Rule>, l: &mut Vec<VariableValue>) {
    if let Some(r) = find_in_chain(t, rule, |r| r.has_msg()) {
        add_variable_origin(RULE_MSG, &r.msg(t), l);
    }
}

/// The properties in the order `RULE` lists them.
type Property = fn(&Transaction<'_>, Option<&Rule>, &mut Vec<VariableValue>);
const PROPERTIES: [(&str, Property); 5] =
    [(RULE_ID, id), (RULE_REV, rev), (RULE_SEVERITY, severity), (RULE_LOGDATA, log_data), (RULE_MSG, msg)];

/// `RULE` (all the properties), `RULE:name` or `RULE:/regex/` (the first
/// property whose name the regex matches).
pub(crate) fn evaluate(selector: &Selector, t: &Transaction<'_>, rule: Option<&Rule>, l: &mut Vec<VariableValue>) {
    match selector {
        Selector::All => {
            for (_, property) in PROPERTIES {
                property(t, rule, l);
            }
        }
        // The element is compared case sensitively; `rev` and
        // `severity` are only resolved inside a rule.
        Selector::Key(e) => {
            let needs_rule = e == RULE_REV || e == RULE_SEVERITY;
            if let Some((_, property)) = PROPERTIES.iter().find(|(name, _)| e == name)
                && (rule.is_some() || !needs_rule)
            {
                property(t, rule, l);
            }
        }
        Selector::Regex(r) => {
            if let Some((_, property)) = PROPERTIES.iter().find(|(name, _)| r.is_match(name.as_bytes())) {
                property(t, rule, l);
            }
        }
    }
}
