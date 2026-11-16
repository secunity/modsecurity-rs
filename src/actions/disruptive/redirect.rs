//! `redirect:URL` — redirects the client (302 unless a 301..307 status was
//! already set), with macro expansion of the URL.

use crate::actions::action::Action;
use crate::actions::context::ActionContext;
use crate::run_time_string::RunTimeString;

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

    fn evaluate(&self, cx: &mut ActionContext<'_, '_, '_>) {
        let url_expanded = cx.expand(&self.string);
        // if it was changed before, lets keep it.
        let status = cx.intervention_status();
        if status == 200 || !(301..=307).contains(&status) {
            cx.set_intervention_status(Self::STATUS);
        }
        cx.set_intervention_url(url_expanded);
        cx.disrupt();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::block::test_support::*;
    use crate::modsecurity::ModSecurity;
    use crate::rule::message::RuleMessage;
    use crate::transaction::Transaction;

    #[test]
    fn redirect() {
        let ms = ModSecurity::new();
        let rules = rules();
        let r = rule(vec![]);
        let mut t = Transaction::new(&ms, &rules, None);
        let mut rm = RuleMessage::new(&r);
        let a = Redirect::with_rts(rts("https://www.example.com/"));
        assert!(a.is_disruptive());

        a.evaluate(&mut ActionContext::new(&mut t, &r, &mut rm));
        assert_eq!((t.outcome.intervention.status, t.outcome.intervention.disruptive), (302, true));
        assert_eq!(t.outcome.intervention.url.as_deref(), Some(&b"https://www.example.com/"[..]));
        assert!(rm.is_disruptive && t.outcome.intervention.log.is_some());

        // A 301..307 status set before is kept, others are replaced.
        t.outcome.intervention.status = 301;
        a.evaluate(&mut ActionContext::new(&mut t, &r, &mut rm));
        assert_eq!(t.outcome.intervention.status, 301);
        t.outcome.intervention.status = 404;
        a.evaluate(&mut ActionContext::new(&mut t, &r, &mut rm));
        assert_eq!(t.outcome.intervention.status, 302);

        // The URL is handed out as raw bytes (C++ copies them unchanged).
        t.outcome.intervention.url = Some(b"/a\xffb".to_vec());
        assert_eq!(t.intervention().unwrap().url.as_deref(), Some(&b"/a\xffb"[..]));
    }
}
