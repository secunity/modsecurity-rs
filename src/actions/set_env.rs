//! Port of `src/actions/set_env.cc`, `src/actions/set_env.h`.
//!
//! `setenv:name=value` — sets an environment variable.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;

use crate::actions::action::Action;
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;
use crate::utils::string::{lossy, ssplit_pair};

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

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, _rm: &mut RuleMessage<'_>) {
        let col_name_expanded = self.string.evaluate(Some(t));
        let (name, value) = ssplit_pair(&col_name_expanded, b'=');
        crate::ms_dbg_a!(t, 8, "Setting environment variable: {} to {}", lossy(&name), lossy(&value));

        // `setenv(3)` with overwrite, as in C++. Names/values with an
        // embedded NUL cannot be represented (C++ silently truncates them);
        // an empty name makes setenv fail with EINVAL, which C++ ignores.
        // `setenv(3)` rejects an empty name and one with `=` (EINVAL,
        // which C++ ignores); `set_var` would panic on those and on NULs.
        let valid = !name.is_empty() && !name.contains(&b'=') && !name.contains(&0) && !value.contains(&0);
        if valid {
            // SAFETY: like the C++ code, this mutates the process
            // environment and is subject to the usual caveat about
            // concurrent getenv(3) calls from other threads.
            unsafe { std::env::set_var(OsStr::from_bytes(&name), OsStr::from_bytes(&value)) };
        }
        // The transaction's view of the environment (the `ENV` variable).
        t.variable_envs.insert(name, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::block::test_support::*;
    use crate::modsecurity::ModSecurity;

    #[test]
    fn setenv() {
        let ms = ModSecurity::new();
        let rules = rules();
        let r = rule(vec![]);
        let mut t = Transaction::new(&ms, &rules, None);
        let mut rm = RuleMessage::new(&r);
        SetENV::with_rts(rts("MSRS_ACTIONS_TEST=a=b")).evaluate(&r, &mut t, &mut rm);
        assert!(has_log(&t, "Setting environment variable: MSRS_ACTIONS_TEST to a=b"));
        assert_eq!(t.variable_envs.get(b"MSRS_ACTIONS_TEST".as_slice()), Some(&b"a=b".to_vec()));
        assert_eq!(std::env::var("MSRS_ACTIONS_TEST").as_deref(), Ok("a=b"));
    }
}
