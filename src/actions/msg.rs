//! Port of `src/actions/msg.cc`, `src/actions/msg.h`.
//!
//! Description: Assigns a custom message to the rule or chain in which it
//! appears. The message will be logged along with every alert.
//!
//! Action Group: Meta-data
//!
//! Example:
//! `SecRule &REQUEST_HEADERS:Host "@eq 0" "log,id:60008,severity:2,msg:'Request Missing a Host Header'"`
//!
//! Note  : The msg information appears in the error and/or audit log files
//!         and is not sent back to the client in response headers.
//!
//! Note 2: The msg action can appear multiple times in the SecRule, however
//!         just the last one will be take into consideration.

use crate::actions::action::Action;
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;
use crate::utils::string::lossy;

#[derive(Debug)]
pub struct Msg {
    pub string: RunTimeString,
}

impl Msg {
    pub fn with_rts(z: RunTimeString) -> Self {
        Msg { string: z }
    }

    pub fn data(&self, t: &Transaction<'_>) -> Vec<u8> {
        self.string.evaluate(Some(t))
    }
}

impl Action for Msg {
    fn name(&self) -> &str {
        "msg"
    }

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, rm: &mut RuleMessage<'_>) {
        let msg = self.data(t);
        crate::ms_dbg_a!(t, 9, "Saving msg: {}", lossy(&msg));
        rm.message = msg;
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
    use crate::modsecurity::ModSecurity;

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
        Msg::with_rts(rts("m1")).evaluate(&r, &mut t, &mut rm);
        assert_eq!(rm.message, b"m1");
        assert!(has_log(&t, "Saving msg: m1"));
        LogData::with_rts(rts("d1")).evaluate(&r, &mut t, &mut rm);
        assert_eq!(rm.data, b"d1");
        Tag::with_rts(rts("t1")).evaluate(&r, &mut t, &mut rm);
        Tag::with_rts(rts("t2")).evaluate(&r, &mut t, &mut rm);
        assert_eq!(rm.tags, vec![b"t1".to_vec(), b"t2".to_vec()]);
        assert!(has_log(&t, "Rule tag: t2"));

        NoLog::new("nolog").evaluate(&r, &mut t, &mut rm);
        assert!(!rm.save_message);
        Log::new("log").evaluate(&r, &mut t, &mut rm);
        assert!(rm.save_message);
        assert!(has_log(&t, "Saving transaction to logs"));
        NoAuditLog::new("noauditlog").evaluate(&r, &mut t, &mut rm);
        assert!(rm.no_audit_log && !rm.save_message);
        AuditLog::new("auditlog").evaluate(&r, &mut t, &mut rm);
        assert!(!rm.no_audit_log && rm.save_message);
    }
}
