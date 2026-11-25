//! `expirevar:collection.variable=seconds` — sets the expiry of a variable
//! of a persistent collection.

use crate::actions::action::Action;
use crate::actions::context::ActionContext;
use crate::collection::Persistent;
use crate::run_time_string::RunTimeString;

#[derive(Debug)]
pub struct ExpireVar {
    string: RunTimeString,
    /// The expression, read when the action is built if it has no macro.
    parsed: Option<Expiry>,
}

/// What an `expirevar` expression says.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Expiry {
    /// The text after `=` is not a number.
    NonNumeric,
    /// No `.` separates a collection from the variable.
    NoCollection,
    /// The collection is not a persistent one.
    InvalidCollection {
        variable: Vec<u8>,
        seconds: u64,
    },
    Valid {
        collection: Persistent,
        variable: Vec<u8>,
        seconds: u64,
    },
}

impl Expiry {
    /// Reads `collection.variable=seconds`. The collection is named in any
    /// case; without `=`, the seconds are 0.
    fn parse(expression: &[u8]) -> Expiry {
        let (fully_qualified_var, seconds) = match expression.iter().position(|&c| c == b'=') {
            None => (expression, 0),
            Some(pos_equals) => {
                let expiry = &expression[pos_equals + 1..];
                if !expiry.iter().all(u8::is_ascii_digit) {
                    return Expiry::NonNumeric;
                }
                // An empty value gives 0; a number too large to hold is the
                // largest.
                let digits = String::from_utf8_lossy(expiry);
                let seconds = if digits.is_empty() { 0 } else { digits.parse().unwrap_or(u64::MAX) };
                (&expression[..pos_equals], seconds)
            }
        };
        let Some(pos_dot) = fully_qualified_var.iter().position(|&c| c == b'.') else {
            return Expiry::NoCollection;
        };
        let variable = fully_qualified_var[pos_dot + 1..].to_vec();
        match Persistent::parse(&fully_qualified_var[..pos_dot]) {
            Some(collection) => Expiry::Valid { collection, variable, seconds },
            None => Expiry::InvalidCollection { variable, seconds },
        }
    }
}

impl ExpireVar {
    pub fn with_rts(z: RunTimeString) -> Self {
        let parsed = (!z.contains_macro()).then(|| Expiry::parse(&z.text()));
        ExpireVar { string: z, parsed }
    }
}

impl Action for ExpireVar {
    fn name(&self) -> &str {
        "expirevar"
    }

    fn evaluate(&self, cx: &mut ActionContext<'_, '_, '_>) {
        let expanded;
        let expiry = match &self.parsed {
            Some(expiry) => expiry,
            None => {
                expanded = Expiry::parse(&cx.expand(&self.string));
                &expanded
            }
        };
        let (variable, seconds) = match expiry {
            Expiry::NonNumeric => {
                crate::ms_dbg!(cx, 5, "Non-numeric expiry seconds found in expirevar expression.");
                return;
            }
            Expiry::NoCollection => {
                crate::ms_dbg!(cx, 5, "No collection found in expirevar expression.");
                return;
            }
            Expiry::InvalidCollection { variable, seconds } => {
                crate::ms_dbg!(
                    cx,
                    5,
                    "Invalid collection found in expirevar expression: collection must be `ip', `global', `resource', `user' or `session'"
                );
                (variable, *seconds)
            }
            Expiry::Valid { collection, variable, seconds } => {
                cx.expire(*collection, variable, *seconds);
                (variable, *seconds)
            }
        };

        // Logged even for an invalid collection.
        crate::ms_dbg!(
            cx,
            9,
            "Setting variable `{}' to expire in {} seconds.",
            String::from_utf8_lossy(variable),
            seconds
        );
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
    fn expire() {
        let ms = ModSecurity::new();
        let rules = rules();
        let r = rule(vec![]);
        let mut t = Transaction::new(&ms, &rules, None);
        let mut rm = RuleMessage::new(&r);
        t.collections.ip.key = b"1.2.3.4".to_vec();
        let app = t.rules.properties.settings.sec_web_app_id.clone().unwrap_or_default();
        t.collections.ip.set(b"foo", app.as_bytes(), b"v").unwrap();
        assert!(t.collections.ip.get(b"foo", app.as_bytes()).unwrap().is_some());

        ExpireVar::with_rts(rts("ip.foo=0")).evaluate(&mut ActionContext::new(&mut t, &r, &mut rm));
        assert!(has_log(&t, "Setting variable `foo' to expire in 0 seconds."));
        assert!(t.collections.ip.get(b"foo", app.as_bytes()).unwrap().is_none());

        ExpireVar::with_rts(rts("ip.foo=1x")).evaluate(&mut ActionContext::new(&mut t, &r, &mut rm));
        assert!(has_log(&t, "Non-numeric expiry seconds found in expirevar expression."));
        ExpireVar::with_rts(rts("foo=10")).evaluate(&mut ActionContext::new(&mut t, &r, &mut rm));
        assert!(has_log(&t, "No collection found in expirevar expression."));
        ExpireVar::with_rts(rts("tx.bar=10")).evaluate(&mut ActionContext::new(&mut t, &r, &mut rm));
        assert!(has_log(
            &t,
            "Invalid collection found in expirevar expression: collection must be `ip', `global', `resource', `user' or `session'"
        ));
        assert!(has_log(&t, "Setting variable `bar' to expire in 10 seconds."));
    }

    /// The collection is named in any case, as everywhere else. (`expirevar`
    /// used to know only lowercase names: `expirevar:IP.foo=0` did
    /// nothing.) The collection key differs from the one of `expire`: the
    /// persistent storage may be shared by tests running at once.
    #[test]
    fn collection_names_ignore_case() {
        use crate::variables::{VariableSelector, new_variable};
        let ms = ModSecurity::new();
        let rules = rules();
        let r = rule(vec![]);
        let app = rules.properties.settings.sec_web_app_id.clone().unwrap_or_default();
        let with_macro = || {
            let mut z = rts("IP.");
            z.append_var(new_variable("TX", VariableSelector::DictElement("name".into())).unwrap());
            z.append_text("=0");
            z
        };
        for (z, static_text) in [(rts("IP.foo=0"), true), (rts("Ip.foo=0"), true), (with_macro(), false)] {
            let mut t = Transaction::new(&ms, &rules, None);
            let mut rm = RuleMessage::new(&r);
            t.collections.tx.set(b"name", b"foo".to_vec());
            t.collections.ip.key = b"192.0.2.7".to_vec();
            t.collections.ip.set(b"foo", app.as_bytes(), b"v").unwrap();
            let action = ExpireVar::with_rts(z);
            assert_eq!(action.parsed.is_some(), static_text);
            action.evaluate(&mut ActionContext::new(&mut t, &r, &mut rm));
            assert!(t.collections.ip.get(b"foo", app.as_bytes()).unwrap().is_none(), "{:?}", action.string);
        }
        assert_eq!(
            Expiry::parse(b"Session.a=5"),
            Expiry::Valid { collection: Persistent::Session, variable: b"a".to_vec(), seconds: 5 }
        );
        assert_eq!(Expiry::parse(b"tx.a"), Expiry::InvalidCollection { variable: b"a".to_vec(), seconds: 0 });
    }
}
