//! Port of `src/actions/disruptive/redirect.cc`, `src/actions/disruptive/redirect.h`.
//!
//! `redirect:URL` — redirects the client (302 unless a 301..307 status was
//! already set), with macro expansion of the URL.

use crate::actions::action::Action;
use crate::rule_message::{CLIENT_LOG_MESSAGE_INFO, RuleMessage};
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct Redirect {
    string: RunTimeString,
}

impl Redirect {
    /// The status sent with the redirection, unless a 301..307 one was set
    /// before.
    const STATUS: i32 = 302;

    pub fn with_rts(z: RunTimeString) -> Self {
        Redirect { string: z }
    }
}

impl Action for Redirect {
    fn name(&self) -> &str {
        // "redirert" (sic): the action name used by C++, kept for identical
        // debug output.
        "redirert"
    }

    fn is_disruptive(&self) -> bool {
        true
    }

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, rm: &mut RuleMessage<'_>) {
        let url_expanded = self.string.evaluate(Some(t));
        // if it was changed before, lets keep it.
        if t.intervention.status == 200 || !(301..=307).contains(&t.intervention.status) {
            t.intervention.status = Self::STATUS;
        }
        t.intervention.url = Some(url_expanded);
        t.intervention.disruptive = true;
        rm.is_disruptive = true;
        t.intervention.log = Some(rm.log(t, CLIENT_LOG_MESSAGE_INFO, -1));
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
        let a = Redirect::with_rts(rts("https://www.example.com/"));
        assert!(a.is_disruptive());

        a.evaluate(&r, &mut t, &mut rm);
        assert_eq!((t.intervention.status, t.intervention.disruptive), (302, true));
        assert_eq!(t.intervention.url.as_deref(), Some(&b"https://www.example.com/"[..]));
        assert!(rm.is_disruptive && t.intervention.log.is_some());

        // A 301..307 status set before is kept, others are replaced.
        t.intervention.status = 301;
        a.evaluate(&r, &mut t, &mut rm);
        assert_eq!(t.intervention.status, 301);
        t.intervention.status = 404;
        a.evaluate(&r, &mut t, &mut rm);
        assert_eq!(t.intervention.status, 302);

        // The URL is handed out as raw bytes (C++ copies them unchanged).
        t.intervention.url = Some(b"/a\xffb".to_vec());
        assert_eq!(t.intervention().unwrap().url.as_deref(), Some(&b"/a\xffb"[..]));
    }
}
