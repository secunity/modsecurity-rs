//! Port of `src/actions/set_sid.cc`, `src/actions/set_sid.h`.
//!
//! `setsid:'...'` — sets the session id (SESSION collection key and SESSIONID).

use crate::actions::action::Action;
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;
use crate::utils::string::lossy;

#[derive(Debug)]
pub struct SetSID {
    pub string: RunTimeString,
}

impl SetSID {
    pub fn with_rts(z: RunTimeString) -> Self {
        SetSID { string: z }
    }
}

impl Action for SetSID {
    fn name(&self) -> &str {
        "setsid"
    }

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, _rm: &mut RuleMessage<'_>) {
        let col_name_expanded = self.string.evaluate(Some(t));
        crate::ms_dbg_a!(t, 8, "Session ID initiated with value: '{}'.", lossy(&col_name_expanded));
        let offset = t.vars.offset;
        t.vars.session_id.set(&col_name_expanded, offset);
        t.collections.session.key = col_name_expanded;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::block::test_support::*;
    use crate::actions::init_col::InitCol;
    use crate::actions::set_rsc::SetRSC;
    use crate::actions::set_uid::SetUID;
    use crate::modsecurity::ModSecurity;

    /// setsid, setuid, setrsc, initcol.
    #[test]
    fn collection_keys() {
        let ms = ModSecurity::new();
        let rules = rules();
        let r = rule(vec![]);
        let mut t = Transaction::new(&ms, &rules, None);
        let mut rm = RuleMessage::new(&r);

        SetSID::with_rts(rts("s1")).evaluate(&r, &mut t, &mut rm);
        assert_eq!(t.collections.session.key, b"s1");
        assert!(has_log(&t, "Session ID initiated with value: 's1'."));
        SetUID::with_rts(rts("u1")).evaluate(&r, &mut t, &mut rm);
        assert_eq!(t.collections.user.key, b"u1");
        assert!(has_log(&t, "User collection initiated with value: 'u1'."));
        SetRSC::with_rts(rts("r1")).evaluate(&r, &mut t, &mut rm);
        assert_eq!(t.collections.resource.key, b"r1");
        assert!(has_log(&t, "RESOURCE initiated with value: 'r1'."));

        for (col, field) in [("ip", 0), ("global", 1), ("resource", 2)] {
            let a = InitCol::with_rts(&format!("initcol:{}=", col), rts("k")).unwrap();
            a.evaluate(&r, &mut t, &mut rm);
            let c = &t.collections;
            let key = [&c.ip.key, &c.global.key, &c.resource.key][field];
            assert_eq!(key, b"k");
            assert!(has_log(&t, &format!("Collection `{}' initialized with value: k", col)));
        }
        let e = |a: &str| InitCol::with_rts(a, rts("x")).unwrap_err();
        assert_eq!(e("initcol:i"), "Something wrong with initcol format: too small");
        assert_eq!(e("initcol:ip"), "Something wrong with initcol format: missing equals sign");
        assert_eq!(
            e("initcol:session="),
            "Something wrong with initcol: collection must be `ip', `global' or `resource'"
        );
    }
}
