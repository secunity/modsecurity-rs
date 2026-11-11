//! Port of `headers/modsecurity/actions/action.h` and `src/actions/action.cc`.
//!
//! The C++ `Action` class hierarchy becomes the [`Action`] trait; the data
//! members of the base class live in [`ActionBase`].

use crate::actions::transformations::transformation::Transformation;
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;
use crate::variables::variable::AsAny;

/// Define the action kind regarding to the execution time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Action that are executed while loading the configuration. For
    /// instance the rule ID or the rule phase.
    ConfigurationKind,
    /// Those are actions that demands to be executed before call the
    /// operator. For instance the transformations.
    RunTimeBeforeMatchAttemptKind,
    /// Actions that are executed after the execution of the operator, only
    /// if the operator returned Match (or True). For instance the
    /// disruptive actions.
    RunTimeOnlyIfMatchKind,
}

/// Data members of the C++ `Action` base class.
#[derive(Debug, Clone)]
pub struct ActionBase {
    pub is_none: bool,
    pub temporary_action: bool,
    pub action_kind: Kind,
    pub name: String,
    pub parser_payload: String,
}

impl ActionBase {
    /// `Action(const std::string &_action)` (kind `RunTimeOnlyIfMatchKind`).
    pub fn new(action: &str) -> Self {
        Self::with_kind(action, Kind::RunTimeOnlyIfMatchKind)
    }

    /// `Action(const std::string &_action, Kind kind)`
    pub fn with_kind(action: &str, kind: Kind) -> Self {
        let mut b = ActionBase {
            is_none: false,
            temporary_action: false,
            action_kind: kind,
            name: String::new(),
            parser_payload: String::new(),
        };
        b.set_name_and_payload(action);
        b
    }

    /// `set_name_and_payload`: splits `name:payload` (a `t:` prefix is part
    /// of the name) and strips single quotes around the payload.
    pub fn set_name_and_payload(&mut self, data: &str) {
        let mut pos = data.find(':');
        if let Some(rest) = data.strip_prefix("t:") {
            pos = rest.find(':').map(|p| p + 2);
        }
        let Some(pos) = pos else {
            self.name = data.to_string();
            return;
        };
        self.name = data[..pos].to_string();
        self.parser_payload = data[pos + 1..].to_string();
        if self.parser_payload.starts_with('\'') && self.parser_payload.len() > 2 {
            self.parser_payload.remove(0);
            self.parser_payload.pop();
        }
    }
}

/// A SecLang action (`phase:2`, `deny`, `setvar:...`, `t:lowercase`, ...).
pub trait Action: AsAny + Send + Sync + std::fmt::Debug {
    fn base(&self) -> &ActionBase;
    fn base_mut(&mut self) -> &mut ActionBase;

    /// `init(std::string *error)`: validates/parses the payload after
    /// construction.
    fn init(&mut self) -> Result<(), String> {
        Ok(())
    }

    fn is_disruptive(&self) -> bool {
        false
    }

    /// `ConfigurationKind` actions are evaluated once, while the rule is
    /// being built (C++: `evaluate(rule, nullptr)` from the
    /// `RuleWithActions` constructor). They configure the rule.
    fn configure(&self, _rule: &mut RuleWithActions) -> bool {
        true
    }

    /// Run time evaluation (`evaluate(rule, transaction, ruleMessage)`).
    fn evaluate(&self, _rule: &RuleWithActions, _t: &mut Transaction<'_>, _rm: &mut RuleMessage<'_>) -> bool {
        true
    }

    /// `dynamic_cast<Transformation *>`
    fn as_transformation(&self) -> Option<&dyn Transformation> {
        None
    }

    fn name(&self) -> &str {
        &self.base().name
    }

    fn action_kind(&self) -> Kind {
        self.base().action_kind
    }
}

impl dyn Action {
    /// `dynamic_cast<T *>`
    pub fn downcast_ref<T: Action>(&self) -> Option<&T> {
        self.as_any().downcast_ref::<T>()
    }

    pub fn is<T: Action>(&self) -> bool {
        self.as_any().is::<T>()
    }
}

/// The plain C++ `Action` class, instantiated by the parser for actions that
/// are accepted but have no behaviour of their own.
#[derive(Debug, Clone)]
pub struct BaseAction {
    pub base: ActionBase,
}

impl BaseAction {
    pub fn new(action: &str) -> Self {
        BaseAction { base: ActionBase::new(action) }
    }

    pub fn with_kind(action: &str, kind: Kind) -> Self {
        BaseAction { base: ActionBase::with_kind(action, kind) }
    }
}

impl Action for BaseAction {
    fn base(&self) -> &ActionBase {
        &self.base
    }
    fn base_mut(&mut self) -> &mut ActionBase {
        &mut self.base
    }
}

/// Implements the `base`/`base_mut` accessors of [`Action`] for a struct
/// with a `base: ActionBase` field. Use inside an `impl Action for T` block.
#[macro_export]
macro_rules! action_base_accessors {
    () => {
        fn base(&self) -> &$crate::actions::action::ActionBase {
            &self.base
        }
        fn base_mut(&mut self) -> &mut $crate::actions::action::ActionBase {
            &mut self.base
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_and_payload() {
        let b = ActionBase::new("phase:2");
        assert_eq!(b.name, "phase");
        assert_eq!(b.parser_payload, "2");
        let b = ActionBase::new("t:lowercase");
        assert_eq!(b.name, "t:lowercase");
        let b = ActionBase::new("msg:'hello'");
        assert_eq!(b.parser_payload, "hello");
        let b = ActionBase::new("deny");
        assert_eq!(b.name, "deny");
    }
}
