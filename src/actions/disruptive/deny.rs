//! `deny` — stops the transaction with the configured status (403 by
//! default).

use crate::actions::action::Action;
use crate::actions::context::ActionContext;

#[derive(Debug)]
pub struct Deny {
    name: String,
}

impl Deny {
    pub fn new(name: &str) -> Self {
        Deny { name: name.to_string() }
    }
}

impl Action for Deny {
    fn name(&self) -> &str {
        &self.name
    }

    fn is_disruptive(&self) -> bool {
        true
    }

    fn evaluate(&self, cx: &mut ActionContext<'_, '_, '_>) {
        crate::ms_dbg!(cx, 8, "Running action deny");
        if cx.intervention_status() == 200 {
            cx.set_intervention_status(403);
        }
        cx.disrupt();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::block::test_support::*;
    use crate::actions::data::status::Status;
    use crate::actions::disruptive::drop::Drop;
    use crate::actions::disruptive::pass::Pass;
    use crate::instance::ModSecurity;
    use crate::rule::message::RuleMessage;
    use crate::transaction::Transaction;

    /// deny, drop, status, pass.
    #[test]
    fn deny_drop_pass() {
        let ms = ModSecurity::new();
        let rules = rules();
        let r = rule(vec![RuleAction::from(Deny::new("deny"))]);
        assert!(r.has_disruptive_action());
        let mut t = Transaction::new(&ms, &rules, None);
        let mut rm = RuleMessage::new(&r);

        Deny::new("deny").evaluate(&mut ActionContext::new(&mut t, &r, &mut rm));
        assert!(has_log(&t, "Running action deny"));
        assert_eq!((t.outcome.intervention.status, t.outcome.intervention.disruptive), (403, true));
        assert!(rm.is_disruptive);
        let log = t.outcome.intervention.log.clone().unwrap();
        assert!(log.contains("ModSecurity: Access denied with code %d (phase 1)."), "{}", log);

        Pass::new("pass").evaluate(&mut ActionContext::new(&mut t, &r, &mut rm));
        assert!(has_log(&t, "Running action pass"));
        assert_eq!(t.outcome.intervention, crate::intervention::Intervention::default());

        // A status set before is kept.
        let s = Status::new("status", "404").unwrap();
        s.evaluate(&mut ActionContext::new(&mut t, &r, &mut rm));
        Drop::new("drop").evaluate(&mut ActionContext::new(&mut t, &r, &mut rm));
        assert!(has_log(&t, "Running action drop [executing deny instead of drop.]"));
        assert_eq!((t.outcome.intervention.status, t.outcome.intervention.disruptive), (404, true));
        assert!(t.outcome.intervention.log.is_some());

        assert_eq!(Status::new("status", "abc").unwrap_err(), "Not a valid number: abc");
    }
}
