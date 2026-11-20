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

        // `setenv(3)` with overwrite. It rejects an empty name and one with
        // `=` (EINVAL), and a name or value with an embedded NUL cannot be
        // passed to it: the process environment is left alone for those,
        // without an error (`set_var` would panic on them).
        let valid = !name.is_empty() && !name.contains(&b'=') && !name.contains(&0) && !value.contains(&0);
        if valid {
            crate::utils::system::set_env(&name, &value);
        }
        // The transaction's view of the environment (the `ENV` variable).
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
        assert_eq!(std::env::var("MSRS_ACTIONS_TEST").as_deref(), Ok("a=b"));
    }
}
