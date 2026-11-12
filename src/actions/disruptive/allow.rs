//! Port of `src/actions/disruptive/allow.cc`, `src/actions/disruptive/allow.h`.
//!
//! `allow`, `allow:phase`, `allow:request` — stops the evaluation of the
//! rules (from now on, for the current phase, or for the request phases).

use crate::actions::action::{Action, ActionBase};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;

/// `AllowType`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowType {
    NoneAllowType,
    RequestAllowType,
    PhaseAllowType,
    FromNowOnAllowType,
}

#[derive(Debug)]
pub struct Allow {
    pub base: ActionBase,
    pub allow_type: AllowType,
}

impl Allow {
    pub fn new(action: &str) -> Self {
        Allow { base: ActionBase::new(action), allow_type: AllowType::NoneAllowType }
    }

    /// `allowTypeToName`
    pub fn allow_type_to_name(a: AllowType) -> &'static str {
        match a {
            AllowType::NoneAllowType => "None",
            AllowType::RequestAllowType => "Request",
            AllowType::PhaseAllowType => "Phase",
            AllowType::FromNowOnAllowType => "FromNowOn",
        }
    }
}

impl Action for Allow {
    crate::action_base_accessors!();

    fn init(&mut self) -> Result<(), String> {
        let a = self.base.parser_payload.to_ascii_lowercase();
        self.allow_type = match a.as_str() {
            "phase" => AllowType::PhaseAllowType,
            "request" => AllowType::RequestAllowType,
            "" => AllowType::FromNowOnAllowType,
            _ => return Err("Allow: if specified, the parameter most be: phase, request".to_string()),
        };
        Ok(())
    }

    fn is_disruptive(&self) -> bool {
        true
    }

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, _rm: &mut RuleMessage<'_>) {
        crate::ms_dbg_a!(
            t,
            4,
            "Dropping the evaluation of upcoming rules in favor of an `allow' action of type: {}",
            Self::allow_type_to_name(self.allow_type)
        );
        t.allow_type = self.allow_type;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::block::test_support::*;
    use crate::modsecurity::ModSecurity;

    #[test]
    fn allow() {
        let ty = |a: &str| {
            let mut x = Allow::new(a);
            x.init().map(|_| x.allow_type)
        };
        assert_eq!(ty("allow"), Ok(AllowType::FromNowOnAllowType));
        assert_eq!(ty("allow:phase"), Ok(AllowType::PhaseAllowType));
        assert_eq!(ty("allow:REQUEST"), Ok(AllowType::RequestAllowType));
        assert_eq!(ty("allow:foo"), Err("Allow: if specified, the parameter most be: phase, request".to_string()));

        let ms = ModSecurity::new();
        let rules = rules();
        let r = rule(vec![]);
        let mut t = Transaction::new(&ms, &rules, None);
        let mut rm = RuleMessage::new(&r);
        let mut a = Allow::new("allow:phase");
        a.init().unwrap();
        a.evaluate(&r, &mut t, &mut rm);
        assert_eq!(t.allow_type, AllowType::PhaseAllowType);
        assert!(has_log(&t, "Dropping the evaluation of upcoming rules in favor of an `allow' action of type: Phase"));
    }
}
