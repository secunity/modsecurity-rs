//! `setenv:name=value` — sets an environment variable.

use crate::actions::action::Action;
use crate::actions::context::ActionContext;
use crate::run_time_string::RunTimeString;
use crate::utils::string::ssplit_pair;

#[derive(Debug)]
pub struct SetENV {
    pub string: RunTimeString,
}

impl SetENV {
    pub fn with_rts(z: RunTimeString) -> Self {
        SetENV { string: z }
    }
}

impl Action for SetENV {
    fn name(&self) -> &str {
        "setenv"
    }

    fn evaluate(&self, cx: &mut ActionContext<'_, '_, '_>) {
        let col_name_expanded = cx.expand(&self.string);
        let (name, value) = ssplit_pair(&col_name_expanded, b'=');
        crate::ms_dbg!(
            cx,
            8,
            "Setting environment variable: {} to {}",
            String::from_utf8_lossy(&name),
            String::from_utf8_lossy(&value)
        );

        // The transaction's own environment: what the `ENV` variable shows
        // and what a program run by `@inspectFile` gets. The environment
        // of the process is not touched.
        cx.set_env(name, value);
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
    fn setenv() {
        let ms = ModSecurity::new();
        let rules = rules();
        let r = rule(vec![]);
        let mut t = Transaction::new(&ms, &rules, None);
        let mut rm = RuleMessage::new(&r);
        SetENV::with_rts(rts("MSRS_ACTIONS_TEST=a=b")).evaluate(&mut ActionContext::new(&mut t, &r, &mut rm));
        assert!(has_log(&t, "Setting environment variable: MSRS_ACTIONS_TEST to a=b"));
        assert_eq!(t.variable_envs.get(b"MSRS_ACTIONS_TEST".as_slice()), Some(&b"a=b".to_vec()));
        // The process and other transactions do not see it.
        assert!(std::env::var_os("MSRS_ACTIONS_TEST").is_none());
        let other = Transaction::new(&ms, &rules, None);
        assert!(other.variable_envs.is_empty());
    }
}
