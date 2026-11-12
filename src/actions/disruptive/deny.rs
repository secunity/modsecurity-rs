//! Port of `src/actions/disruptive/deny.cc`, `src/actions/disruptive/deny.h`.
//!
//! `deny` — stops the transaction with the configured status (403 by
//! default).

use crate::actions::action::{Action, ActionBase};
use crate::rule_message::{CLIENT_LOG_MESSAGE_INFO, RuleMessage};
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct Deny {
    pub base: ActionBase,
}

impl Deny {
    pub fn new(action: &str) -> Self {
        Deny { base: ActionBase::new(action) }
    }
}

impl Action for Deny {
    crate::action_base_accessors!();

    fn is_disruptive(&self) -> bool {
        true
    }

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, rm: &mut RuleMessage<'_>) {
        crate::ms_dbg_a!(t, 8, "Running action deny");
        if t.intervention.status == 200 {
            t.intervention.status = 403;
        }
        t.intervention.disruptive = true;
        rm.is_disruptive = true;
        t.intervention.log = Some(rm.log(t, CLIENT_LOG_MESSAGE_INFO, -1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::block::test_support::*;
    use crate::actions::data::status::Status;
    use crate::actions::disruptive::drop::Drop;
    use crate::actions::disruptive::pass::Pass;
    use crate::modsecurity::ModSecurity;

    /// deny, drop, status, pass.
    #[test]
    fn deny_drop_pass() {
        let ms = ModSecurity::new();
        let rules = rules();
        let r = rule(vec![RuleAction::Other(Box::new(Deny::new("deny")))]);
        assert!(r.has_disruptive_action());
        let mut t = Transaction::new(&ms, &rules, None);
        let mut rm = RuleMessage::new(&r);

        Deny::new("deny").evaluate(&r, &mut t, &mut rm);
        assert!(has_log(&t, "Running action deny"));
        assert_eq!((t.intervention.status, t.intervention.disruptive), (403, true));
        assert!(rm.is_disruptive);
        let log = t.intervention.log.clone().unwrap();
        assert!(log.contains("ModSecurity: Access denied with code %d (phase 1)."), "{}", log);

        Pass::new("pass").evaluate(&r, &mut t, &mut rm);
        assert!(has_log(&t, "Running action pass"));
        assert_eq!(t.intervention, crate::intervention::Intervention::default());

        // A status set before is kept.
        let mut s = Status::new("status:404");
        s.init().unwrap();
        s.evaluate(&r, &mut t, &mut rm);
        Drop::new("drop").evaluate(&r, &mut t, &mut rm);
        assert!(has_log(&t, "Running action drop [executing deny instead of drop.]"));
        assert_eq!((t.intervention.status, t.intervention.disruptive), (404, true));
        assert!(t.intervention.log.is_some());

        assert_eq!(Status::new("status:abc").init(), Err("Not a valid number: abc".to_string()));
    }
}
