//! Port of `src/actions/disruptive/redirect.cc`, `src/actions/disruptive/redirect.h`.
//!
//! `redirect:URL` — redirects the client (302 unless a 301..307 status was
//! already set), with macro expansion of the URL.

use crate::actions::action::{Action, ActionBase};
use crate::intervention::{free_log, free_url, strdup, strdup_bytes};
use crate::rule_message::{CLIENT_LOG_MESSAGE_INFO, RuleMessage};
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct Redirect {
    pub base: ActionBase,
    status: i32,
    pub string: RunTimeString,
}

impl Redirect {
    pub fn with_rts(z: RunTimeString) -> Self {
        // "redirert" (sic): the action name used by C++, kept for identical
        // debug output.
        Redirect { base: ActionBase::new("redirert"), status: 0, string: z }
    }
}

impl Action for Redirect {
    crate::action_base_accessors!();

    fn init(&mut self) -> Result<(), String> {
        self.status = 302;
        Ok(())
    }

    fn is_disruptive(&self) -> bool {
        true
    }

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, rm: &mut RuleMessage<'_>) -> bool {
        let url_expanded = self.string.evaluate(Some(t));

        // if it was changed before, lets keep it.
        if t.it.status == 200 || !(301..=307).contains(&t.it.status) {
            t.it.status = self.status;
        }

        free_url(&mut t.it);
        t.it.url = strdup_bytes(&url_expanded);
        t.it.disruptive = 1;
        free_log(&mut t.it);
        rm.is_disruptive = true;
        let log = rm.log(t, CLIENT_LOG_MESSAGE_INFO, -1);
        t.it.log = strdup(&log);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::block::test_support::*;
    use crate::modsecurity::ModSecurity;

    #[test]
    fn redirect() {
        let ms = ModSecurity::new();
        let rules = rules();
        let r = rule(vec![]);
        let mut t = Transaction::new(&ms, &rules, None);
        let mut rm = RuleMessage::new(&r);
        let mut a = Redirect::with_rts(rts("https://www.example.com/"));
        a.init().unwrap();
        assert!(a.is_disruptive());

        a.evaluate(&r, &mut t, &mut rm);
        assert_eq!((t.it.status, t.it.disruptive), (302, 1));
        assert_eq!(t.it.url_str().as_deref(), Some("https://www.example.com/"));
        assert!(rm.is_disruptive && t.it.log_str().is_some());

        // A 301..307 status set before is kept, others are replaced.
        t.it.status = 301;
        a.evaluate(&r, &mut t, &mut rm);
        assert_eq!(t.it.status, 301);
        t.it.status = 404;
        a.evaluate(&r, &mut t, &mut rm);
        assert_eq!(t.it.status, 302);
        crate::intervention::free(&mut t.it);
    }
}
