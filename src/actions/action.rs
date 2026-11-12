//! Port of `headers/modsecurity/actions/action.h` and `src/actions/action.cc`.
//!
//! The C++ `Action` class hierarchy becomes the [`Action`] trait. There is
//! no shared base data: an action keeps its name (as written in the rule)
//! and whatever it parsed from its payload.

use crate::actions::transformations::transformation::Transformation;
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;

/// When an action runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Applied once to the rule while the configuration is loaded. For
    /// instance the rule id or the rule phase.
    Configuration,
    /// Executed before the operator is called: the transformations.
    RunTimeBeforeMatchAttempt,
    /// Executed after the operator matched. For instance the disruptive
    /// actions.
    RunTimeOnlyIfMatch,
}

/// Splits the text of an action into its name and payload
/// (`name:payload`; a `t:` prefix is part of the name), stripping single
/// quotes around the payload. The name keeps the spelling of the rule: it
/// is what the debug log prints and what `block`/`setvar` are recognised by.
pub fn name_and_payload(data: &str) -> (&str, &str) {
    let pos = match data.strip_prefix("t:") {
        Some(rest) => rest.find(':').map(|p| p + 2),
        None => data.find(':'),
    };
    let Some(pos) = pos else {
        return (data, "");
    };
    let payload = &data[pos + 1..];
    let payload = if payload.starts_with('\'') && payload.len() > 2 {
        // The last character goes with the opening quote, whatever it is.
        let end = payload.char_indices().next_back().map_or(1, |(i, _)| i);
        &payload[1..end]
    } else {
        payload
    };
    (&data[..pos], payload)
}

/// The name part of [`name_and_payload`].
pub fn name_of(data: &str) -> String {
    name_and_payload(data).0.to_string()
}

/// A SecLang action (`phase:2`, `deny`, `setvar:...`, `t:lowercase`, ...).
///
/// Actions are built from their rule text by constructors that parse and
/// validate the payload; an action is either applied to its rule once
/// ([`Action::configure`]) or evaluated when the rule matches
/// ([`Action::evaluate`]), depending on its [`Kind`].
pub trait Action: Send + Sync + std::fmt::Debug {
    /// The action name, as written in the rule.
    fn name(&self) -> &str;

    fn kind(&self) -> Kind {
        Kind::RunTimeOnlyIfMatch
    }

    fn is_disruptive(&self) -> bool {
        false
    }

    /// Whether this is the `block` action, which rules treat apart from the
    /// other actions.
    fn is_block(&self) -> bool {
        false
    }

    /// [`Kind::Configuration`] actions are applied once, while the rule is
    /// being built.
    fn configure(&self, _rule: &mut RuleWithActions) {}

    /// Run time evaluation.
    fn evaluate(&self, _rule: &RuleWithActions, _t: &mut Transaction<'_>, _rm: &mut RuleMessage<'_>) {}

    /// The `(prefix, href)` of an `xmlns` action, used by the `XML`
    /// variable.
    fn xml_namespace(&self) -> Option<(&str, &str)> {
        None
    }

    /// The transformation, if this action is one.
    fn as_transformation(&self) -> Option<&Transformation> {
        None
    }
}

/// An action that is accepted but has no behaviour of its own (the plain
/// C++ `Action` class).
#[derive(Debug, Clone)]
pub struct InertAction {
    name: String,
}

impl InertAction {
    pub fn new(action: &str) -> Self {
        InertAction { name: name_of(action) }
    }
}

impl Action for InertAction {
    fn name(&self) -> &str {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_and_payload_split() {
        assert_eq!(name_and_payload("phase:2"), ("phase", "2"));
        assert_eq!(name_and_payload("t:lowercase"), ("t:lowercase", ""));
        assert_eq!(name_and_payload("t:foo:bar"), ("t:foo", "bar"));
        assert_eq!(name_and_payload("msg:'hello'"), ("msg", "hello"));
        assert_eq!(name_and_payload("deny"), ("deny", ""));
        assert_eq!(name_and_payload("ctl:ruleRemoveById=1"), ("ctl", "ruleRemoveById=1"));
        // Quotes are only stripped from payloads longer than two bytes,
        // and the last character goes whatever it is.
        assert_eq!(name_and_payload("a:''"), ("a", "''"));
        assert_eq!(name_and_payload("a:'x'"), ("a", "x"));
        assert_eq!(name_and_payload("a:'xy"), ("a", "x"));
    }
}
