//! Port of `src/actions/expire_var.cc`, `src/actions/expire_var.h`.
//!
//! `expirevar:collection.variable=seconds` — sets the expiry of a variable
//! of a persistent collection.

use crate::actions::action::Action;
use crate::collection::Persistent;
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;
use crate::utils::string::{atoi, lossy};

#[derive(Debug)]
pub struct ExpireVar {
    pub string: RunTimeString,
}

impl ExpireVar {
    pub fn with_rts(z: RunTimeString) -> Self {
        ExpireVar { string: z }
    }
}

impl Action for ExpireVar {
    fn name(&self) -> &str {
        "expirevar"
    }

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, _rm: &mut RuleMessage<'_>) {
        let expire_expression_expanded = self.string.evaluate(Some(t));
        let mut expiry_seconds: i32 = 0;

        let fully_qualified_var: &[u8] = match expire_expression_expanded.iter().position(|&c| c == b'=') {
            None => &expire_expression_expanded,
            Some(pos_equals) => {
                let expiry = &expire_expression_expanded[pos_equals + 1..];
                if expiry.iter().all(u8::is_ascii_digit) {
                    // C++ `atoi` (an empty value gives 0).
                    expiry_seconds = atoi(expiry) as i32;
                } else {
                    crate::ms_dbg_a!(t, 5, "Non-numeric expiry seconds found in expirevar expression.");
                    return;
                }
                &expire_expression_expanded[..pos_equals]
            }
        };

        let Some(pos_dot) = fully_qualified_var.iter().position(|&c| c == b'.') else {
            crate::ms_dbg_a!(t, 5, "No collection found in expirevar expression.");
            return;
        };

        let collection = &fully_qualified_var[..pos_dot];
        let variable_name = &fully_qualified_var[pos_dot + 1..];

        let target = match collection {
            b"ip" => Some(Persistent::Ip),
            b"global" => Some(Persistent::Global),
            b"resource" => Some(Persistent::Resource),
            b"session" => Some(Persistent::Session),
            b"user" => Some(Persistent::User),
            _ => None,
        };
        match target {
            Some(collection) => {
                t.collections.persistent(collection).set_expiry(
                    variable_name,
                    t.rules.properties.web_app_id(),
                    expiry_seconds,
                );
            }
            None => {
                crate::ms_dbg_a!(
                    t,
                    5,
                    "Invalid collection found in expirevar expression: collection must be `ip', `global', `resource', `user' or `session'"
                );
            }
        }

        // Logged even for an invalid collection (as in C++).
        crate::ms_dbg_a!(t, 9, "Setting variable `{}' to expire in {} seconds.", lossy(variable_name), expiry_seconds);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::block::test_support::*;
    use crate::modsecurity::ModSecurity;

    #[test]
    fn expire() {
        let ms = ModSecurity::new();
        let rules = rules();
        let r = rule(vec![]);
        let mut t = Transaction::new(&ms, &rules, None);
        let mut rm = RuleMessage::new(&r);
        t.collections.ip.key = b"1.2.3.4".to_vec();
        let app = t.rules.properties.sec_web_app_id.clone().unwrap_or_default();
        t.collections.ip.set(b"foo", app.as_bytes(), b"v");
        assert!(t.collections.ip.get(b"foo", app.as_bytes()).is_some());

        ExpireVar::with_rts(rts("ip.foo=0")).evaluate(&r, &mut t, &mut rm);
        assert!(has_log(&t, "Setting variable `foo' to expire in 0 seconds."));
        assert!(t.collections.ip.get(b"foo", app.as_bytes()).is_none());

        ExpireVar::with_rts(rts("ip.foo=1x")).evaluate(&r, &mut t, &mut rm);
        assert!(has_log(&t, "Non-numeric expiry seconds found in expirevar expression."));
        ExpireVar::with_rts(rts("foo=10")).evaluate(&r, &mut t, &mut rm);
        assert!(has_log(&t, "No collection found in expirevar expression."));
        ExpireVar::with_rts(rts("tx.bar=10")).evaluate(&r, &mut t, &mut rm);
        assert!(has_log(
            &t,
            "Invalid collection found in expirevar expression: collection must be `ip', `global', `resource', `user' or `session'"
        ));
        assert!(has_log(&t, "Setting variable `bar' to expire in 10 seconds."));
    }
}
