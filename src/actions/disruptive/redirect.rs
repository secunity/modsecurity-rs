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
    const STATUS: u16 = 302;

    pub fn with_rts(z: RunTimeString) -> Self {
        Redirect { string: z }
    }
}

impl Action for Redirect {
    fn name(&self) -> &str {
        "redirect"
    }

    fn is_disruptive(&self) -> bool {
        true
    }

    fn evaluate(&self, cx: &mut ActionContext<'_, '_, '_>) {
        let url_expanded = cx.expand(&self.string);
        // A redirection status set before (by `status`) is kept.
        let status = match cx.intervention_status() {
            Some(status @ 301..=307) => status,
            _ => Self::STATUS,
        };
        cx.disrupt(status, Some(url_expanded));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::block::test_support::*;
    use crate::instance::ModSecurity;
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
        assert_eq!(a.name(), "redirect");

        a.evaluate(&mut ActionContext::new(&mut t, &r, &mut rm));
        assert!(rm.is_disruptive);
        let it = t.intervention().unwrap();
        assert_eq!((it.status, it.url.as_deref()), (302, Some(&b"https://www.example.com/"[..])));
        assert!(!it.log.is_empty());

        // A 301..307 status set before is kept, others are replaced.
        t.outcome.intervention.set_status(301);
        a.evaluate(&mut ActionContext::new(&mut t, &r, &mut rm));
        assert_eq!(t.outcome.intervention.status(), Some(301));
        t.outcome.intervention.set_status(404);
        a.evaluate(&mut ActionContext::new(&mut t, &r, &mut rm));
        assert_eq!(t.outcome.intervention.status(), Some(302));

        // The URL is handed out as raw bytes, unchanged.
        let log = crate::intervention::InterventionLog::Text("redirect");
        t.outcome.intervention.disrupt(302, Some(b"/a\xffb".to_vec()), log);
        assert_eq!(t.intervention().unwrap().url.as_deref(), Some(&b"/a\xffb"[..]));
    }
}
