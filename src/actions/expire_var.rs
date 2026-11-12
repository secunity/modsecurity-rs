//! Port of `src/actions/expire_var.cc`, `src/actions/expire_var.h`.
//!
//! `expirevar:collection.variable=seconds` — sets the expiry of a variable
//! of a persistent collection.

use crate::actions::action::{Action, ActionBase};
use crate::collection::collection::Collection;
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;
use crate::utils::string::{atoi, lossy};

#[derive(Debug)]
pub struct ExpireVar {
    pub base: ActionBase,
    pub string: RunTimeString,
}

impl ExpireVar {
    pub fn with_rts(z: RunTimeString) -> Self {
        ExpireVar { base: ActionBase::new("expirevar"), string: z }
    }
}

impl Action for ExpireVar {
    crate::action_base_accessors!();

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

        // C++ builds the matching `*_DynamicElement` variable and calls its
        // (static) `setExpiry`, which forwards to the collection with the
        // collection key and the web application id as compartments.
        let cols = &t.collections;
        let target: Option<(&dyn Collection, &[u8])> = match collection {
            b"ip" => Some((cols.ip_collection, &cols.ip_collection_key)),
            b"global" => Some((cols.global_collection, &cols.global_collection_key)),
            b"resource" => Some((cols.resource_collection, &cols.resource_collection_key)),
            b"session" => Some((cols.session_collection, &cols.session_collection_key)),
            b"user" => Some((cols.user_collection, &cols.user_collection_key)),
            _ => None,
        };
        match target {
            Some((c, key)) => {
                let web_app_id = t.rules.properties.web_app_id();
                c.set_expiry_c(variable_name, key, Some(web_app_id), expiry_seconds);
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
        t.collections.ip_collection_key = b"1.2.3.4".to_vec();
        let app = t.rules.properties.sec_web_app_id.clone().unwrap_or_default();
        let c = t.collections.ip_collection;
        c.store_or_update_first_c(b"foo", b"1.2.3.4", Some(app.as_bytes()), b"v");
        assert!(c.resolve_first_c(b"foo", b"1.2.3.4", Some(app.as_bytes())).is_some());

        ExpireVar::with_rts(rts("ip.foo=0")).evaluate(&r, &mut t, &mut rm);
        assert!(has_log(&t, "Setting variable `foo' to expire in 0 seconds."));
        assert!(c.resolve_first_c(b"foo", b"1.2.3.4", Some(app.as_bytes())).is_none());

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
