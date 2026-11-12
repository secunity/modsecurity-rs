//! Port of `src/actions/disruptive/allow.cc`, `src/actions/disruptive/allow.h`.
//!
//! `allow`, `allow:phase`, `allow:request` — stops the evaluation of the
//! rules (from now on, for the current phase, or for the request phases).

use crate::actions::action::{Action, name_and_payload};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;

/// What an `allow` action lets through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowType {
    /// `allow:request`: the rest of the request phases.
    Request,
    /// `allow:phase`: the rest of the current phase.
    Phase,
    /// `allow`: everything but the logging phase.
    FromNowOn,
}

#[derive(Debug)]
pub struct Allow {
    name: String,
    allow_type: AllowType,
}

impl Allow {
    /// `allow`, `allow:phase` or `allow:request`.
    pub fn new(action: &str) -> Result<Self, String> {
        let (name, payload) = name_and_payload(action);
        let allow_type = match payload.to_ascii_lowercase().as_str() {
            "phase" => AllowType::Phase,
            "request" => AllowType::Request,
            "" => AllowType::FromNowOn,
            _ => return Err("Allow: if specified, the parameter most be: phase, request".to_string()),
        };
        Ok(Allow { name: name.to_string(), allow_type })
    }

    /// `allowTypeToName`
    fn allow_type_to_name(a: AllowType) -> &'static str {
        match a {
            AllowType::Request => "Request",
            AllowType::Phase => "Phase",
            AllowType::FromNowOn => "FromNowOn",
        }
    }
}

impl Action for Allow {
    fn name(&self) -> &str {
        &self.name
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
        t.allow_type = Some(self.allow_type);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::block::test_support::*;
    use crate::modsecurity::ModSecurity;

    #[test]
    fn allow() {
        let ty = |a: &str| Allow::new(a).map(|x| x.allow_type);
        assert_eq!(ty("allow"), Ok(AllowType::FromNowOn));
        assert_eq!(ty("allow:phase"), Ok(AllowType::Phase));
        assert_eq!(ty("allow:REQUEST"), Ok(AllowType::Request));
        assert_eq!(ty("allow:foo"), Err("Allow: if specified, the parameter most be: phase, request".to_string()));

        let ms = ModSecurity::new();
        let rules = rules();
        let r = rule(vec![]);
        let mut t = Transaction::new(&ms, &rules, None);
        let mut rm = RuleMessage::new(&r);
        let a = Allow::new("allow:phase").unwrap();
        a.evaluate(&r, &mut t, &mut rm);
        assert_eq!(t.allow_type, Some(AllowType::Phase));
        assert!(has_log(&t, "Dropping the evaluation of upcoming rules in favor of an `allow' action of type: Phase"));
    }
}
