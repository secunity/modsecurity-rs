//! `msg:'...'` — the message (with macro expansion) logged with the rule
//! match.
//!
//! The message of a rule or a chain goes to the error and audit logs; it
//! is never sent to the client. A rule may have several `msg` actions: the
//! last one counts. For instance:
//!
//! ```text
//! SecRule &REQUEST_HEADERS:Host "@eq 0" "id:60008,log,msg:'Request Missing a Host Header'"
//! ```

use crate::actions::action::Action;
use crate::actions::context::ActionContext;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct Msg {
    pub string: RunTimeString,
}

impl Msg {
    pub fn with_rts(z: RunTimeString) -> Self {
        Msg { string: z }
    }

    pub fn data(&self, t: &Transaction<'_>) -> Vec<u8> {
        self.string.expand(t, None).into_owned()
    }
}

impl Action for Msg {
    fn name(&self) -> &str {
        "msg"
    }

    fn evaluate(&self, cx: &mut ActionContext<'_, '_, '_>) {
        let msg = cx.expand(&self.string);
        crate::ms_dbg!(cx, 9, "Saving msg: {}", String::from_utf8_lossy(&msg));
        cx.set_message(msg);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::audit_log::AuditLog;
    use crate::actions::block::test_support::*;
    use crate::actions::log::Log;
    use crate::actions::log_data::LogData;
    use crate::actions::no_audit_log::NoAuditLog;
    use crate::actions::no_log::NoLog;
    use crate::actions::tag::Tag;
    use crate::instance::ModSecurity;
    use crate::rule::message::RuleMessage;

    /// msg, logdata, tag, log, nolog, auditlog, noauditlog.
    #[test]
    fn message_actions() {
        let ms = ModSecurity::new();
        let rules = rules();
        let r = rule(vec![RuleAction::Msg(Msg::with_rts(rts("hello"))), RuleAction::Tag(Tag::with_rts(rts("a/b")))]);
        assert!(r.has_msg());
        let mut t = Transaction::new(&ms, &rules, None);
        assert_eq!(r.msg(&t), b"hello");
        assert!(r.contains_tag("a/b", &t));

        let mut rm = RuleMessage::new(&r);
        Msg::with_rts(rts("m1")).evaluate(&mut ActionContext::new(&mut t, &r, &mut rm));
        assert_eq!(rm.message, b"m1");
        assert!(has_log(&t, "Saving msg: m1"));
        LogData::with_rts(rts("d1")).evaluate(&mut ActionContext::new(&mut t, &r, &mut rm));
        assert_eq!(rm.data, b"d1");
        Tag::with_rts(rts("t1")).evaluate(&mut ActionContext::new(&mut t, &r, &mut rm));
        Tag::with_rts(rts("t2")).evaluate(&mut ActionContext::new(&mut t, &r, &mut rm));
        assert_eq!(rm.tags, vec![b"t1".to_vec(), b"t2".to_vec()]);
        assert!(has_log(&t, "Rule tag: t2"));

        NoLog::new("nolog").evaluate(&mut ActionContext::new(&mut t, &r, &mut rm));
        assert!(!rm.save_message);
        Log::new("log").evaluate(&mut ActionContext::new(&mut t, &r, &mut rm));
        assert!(rm.save_message);
        assert!(has_log(&t, "Saving transaction to logs"));
        NoAuditLog::new("noauditlog").evaluate(&mut ActionContext::new(&mut t, &r, &mut rm));
        assert!(rm.no_audit_log && !rm.save_message);
        AuditLog::new("auditlog").evaluate(&mut ActionContext::new(&mut t, &r, &mut rm));
        assert!(!rm.no_audit_log && rm.save_message);
    }
}
