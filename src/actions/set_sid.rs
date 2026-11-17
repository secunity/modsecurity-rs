//! `setsid:'...'` — sets the session id (SESSION collection key and SESSIONID).

use crate::actions::action::Action;
use crate::actions::context::ActionContext;
use crate::run_time_string::RunTimeString;
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

    fn evaluate(&self, cx: &mut ActionContext<'_, '_, '_>) {
        let col_name_expanded = cx.expand(&self.string);
        crate::ms_dbg!(cx, 8, "Session ID initiated with value: '{}'.", lossy(&col_name_expanded));
        cx.set_session_id(col_name_expanded);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::block::test_support::*;
    use crate::actions::init_col::InitCol;
    use crate::actions::set_rsc::SetRSC;
    use crate::actions::set_uid::SetUID;
    use crate::instance::ModSecurity;
    use crate::rule::message::RuleMessage;
    use crate::transaction::Transaction;

    /// setsid, setuid, setrsc, initcol.
    #[test]
    fn collection_keys() {
        let ms = ModSecurity::new();
        let rules = rules();
        let r = rule(vec![]);
        let mut t = Transaction::new(&ms, &rules, None);
        let mut rm = RuleMessage::new(&r);

        SetSID::with_rts(rts("s1")).evaluate(&mut ActionContext::new(&mut t, &r, &mut rm));
        assert_eq!(t.collections.session.key, b"s1");
        assert!(has_log(&t, "Session ID initiated with value: 's1'."));
        SetUID::with_rts(rts("u1")).evaluate(&mut ActionContext::new(&mut t, &r, &mut rm));
        assert_eq!(t.collections.user.key, b"u1");
        assert!(has_log(&t, "User collection initiated with value: 'u1'."));
        SetRSC::with_rts(rts("r1")).evaluate(&mut ActionContext::new(&mut t, &r, &mut rm));
        assert_eq!(t.collections.resource.key, b"r1");
        assert!(has_log(&t, "RESOURCE initiated with value: 'r1'."));

        for (col, field) in [("ip", 0), ("global", 1), ("resource", 2)] {
            let a = InitCol::with_rts("initcol", &format!("{}=", col), rts("k")).unwrap();
            a.evaluate(&mut ActionContext::new(&mut t, &r, &mut rm));
            let c = &t.collections;
            let key = [&c.ip.key, &c.global.key, &c.resource.key][field];
            assert_eq!(key, b"k");
            assert!(has_log(&t, &format!("Collection `{}' initialized with value: k", col)));
        }
        let e = |a: &str| {
            let (name, payload) = crate::actions::action::name_and_payload(a);
            InitCol::with_rts(name, payload, rts("x")).unwrap_err()
        };
        assert_eq!(e("initcol:i"), "Something wrong with initcol format: too small");
        assert_eq!(e("initcol:ip"), "Something wrong with initcol format: missing equals sign");
        assert_eq!(
            e("initcol:session="),
            "Something wrong with initcol: collection must be `ip', `global' or `resource'"
        );
    }
}
