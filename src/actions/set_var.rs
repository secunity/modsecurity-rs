//! `setvar:tx.name=value`, `setvar:tx.name=+N`, `setvar:tx.name=-N`,
//! `setvar:tx.name`, `setvar:!tx.name` — creates, updates or removes a
//! variable of the TX or of a persistent collection.

use crate::actions::action::Action;
use crate::actions::context::ActionContext;
use crate::run_time_string::RunTimeString;
use crate::variables::variable::{Variable, WriteTarget};
use modsecurity_compat::cnum::atoll;

/// Each operation owns exactly the operand it needs. Bare assignment and
/// removal cannot accidentally carry an ignored predicate.
#[derive(Debug)]
pub enum SetVarOperation {
    Set(RunTimeString),
    Add(RunTimeString),
    Subtract(RunTimeString),
    SetToOne,
    Unset,
}

#[derive(Debug)]
pub struct SetVar {
    variable: Variable,
    operation: SetVarOperation,
}

impl SetVar {
    pub fn new(variable: Variable, operation: SetVarOperation) -> Self {
        Self { variable, operation }
    }
}

impl Action for SetVar {
    fn name(&self) -> &str {
        "setvar"
    }

    fn evaluate(&self, cx: &mut ActionContext<'_, '_, '_>) {
        // Part of the engine: resolves and writes any variable.
        let (t, rule) = cx.engine();
        let resolved_pre = match &self.operation {
            SetVarOperation::Set(s) | SetVarOperation::Add(s) | SetVarOperation::Subtract(s) => {
                s.evaluate_rule(Some(t), Some(rule))
            }
            SetVarOperation::SetToOne | SetVarOperation::Unset => Vec::new(),
        };

        let target = self.variable.write_target();
        let variable_name_expanded = match &target {
            Some(target) => target.name().evaluate_rule(Some(t), Some(rule)),
            None => self.variable.name().as_bytes().to_vec(),
        };

        let target_value: Vec<u8> = match &self.operation {
            SetVarOperation::Set(_) => resolved_pre,
            SetVarOperation::SetToOne => b"1".to_vec(),
            SetVarOperation::Unset => {
                if let Some(target) = target {
                    target.remove(t, &variable_name_expanded);
                }
                return;
            }
            SetVarOperation::Add(_) | SetVarOperation::Subtract(_) => {
                // A value counts as the integer it starts with, 0 when it
                // starts with none.
                let pre = atoll(&resolved_pre);
                // The result stops at the ends of the 64 bit range.
                let add = matches!(self.operation, SetVarOperation::Add(_));
                let apply = |value: i64| if add { value.saturating_add(pre) } else { value.saturating_sub(pre) };

                // A persistent collection is shared with the other
                // transactions, threads and processes: it reads and writes
                // the value in one step, so that no other one's change in
                // between is lost.
                if let Some(WriteTarget::Persistent { collection, .. }) = &target {
                    let app = t.rules.properties.web_app_id();
                    let mut compute = |v: Option<&[u8]>| apply(v.map_or(0, atoll)).to_string().into_bytes();
                    let updated =
                        t.collections.persistent(*collection).update(&variable_name_expanded, app, &mut compute);
                    if let Some(value) = t.stored(updated.map(Some)) {
                        crate::ms_dbg!(
                            t,
                            8,
                            "Saving variable: {}:{} with value: {}",
                            self.variable.collection_name(),
                            String::from_utf8_lossy(&variable_name_expanded),
                            String::from_utf8_lossy(&value)
                        );
                    }
                    return;
                }

                let mut l = Vec::new();
                // The variable sees the rule only when it is a `SecRule`.
                let rr = Some(rule).filter(|r| r.is_sec_rule());
                self.variable.evaluate(t, rr, &mut l);
                let value = l.first().map(|v| atoll(v.value())).unwrap_or(0);
                apply(value).to_string().into_bytes()
            }
        };

        crate::ms_dbg!(
            t,
            8,
            "Saving variable: {}:{} with value: {}",
            self.variable.collection_name(),
            String::from_utf8_lossy(&variable_name_expanded),
            String::from_utf8_lossy(&target_value)
        );

        if let Some(target) = target {
            target.store(t, &variable_name_expanded, target_value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::block::test_support::*;
    use crate::instance::ModSecurity;
    use crate::rule::message::RuleMessage;
    use crate::transaction::Transaction;

    use SetVarOperation::{Add, Set, SetToOne, Subtract, Unset};

    fn setvar(name: &str, operation: SetVarOperation) -> SetVar {
        SetVar::new(tx(name), operation)
    }

    #[test]
    fn operations() {
        let ms = ModSecurity::new();
        let rules = rules();
        let r = rule(vec![]);
        let mut t = Transaction::new(&ms, &rules, None);
        let mut rm = RuleMessage::new(&r);
        let tx = |t: &Transaction<'_>, k: &str| t.collections.tx.get(k.as_bytes()).map(<[u8]>::to_vec);

        setvar("foo", Set(rts("abc"))).evaluate(&mut ActionContext::new(&mut t, &r, &mut rm));
        assert_eq!(tx(&t, "foo"), Some(b"abc".to_vec()));
        assert!(has_log(&t, "Saving variable: TX:foo with value: abc"));

        setvar("one", SetToOne).evaluate(&mut ActionContext::new(&mut t, &r, &mut rm));
        assert_eq!(tx(&t, "one"), Some(b"1".to_vec()));

        setvar("score", Add(rts("5"))).evaluate(&mut ActionContext::new(&mut t, &r, &mut rm));
        assert_eq!(tx(&t, "score"), Some(b"5".to_vec()));
        setvar("score", Add(rts("10"))).evaluate(&mut ActionContext::new(&mut t, &r, &mut rm));
        assert_eq!(tx(&t, "score"), Some(b"15".to_vec()));
        setvar("score", Subtract(rts("20"))).evaluate(&mut ActionContext::new(&mut t, &r, &mut rm));
        assert_eq!(tx(&t, "score"), Some(b"-5".to_vec()));
        assert!(has_log(&t, "Saving variable: TX:score with value: -5"));

        // Non numeric operands count as 0.
        setvar("score", Add(rts("x"))).evaluate(&mut ActionContext::new(&mut t, &r, &mut rm));
        assert_eq!(tx(&t, "score"), Some(b"-5".to_vec()));
        setvar("foo", Add(rts("3"))).evaluate(&mut ActionContext::new(&mut t, &r, &mut rm));
        assert_eq!(tx(&t, "foo"), Some(b"3".to_vec()));
        // A number beyond 32 bits is a number.
        setvar("big", Add(rts("99999999999"))).evaluate(&mut ActionContext::new(&mut t, &r, &mut rm));
        assert_eq!(tx(&t, "big"), Some(b"99999999999".to_vec()));

        setvar("foo", Unset).evaluate(&mut ActionContext::new(&mut t, &r, &mut rm));
        assert_eq!(tx(&t, "foo"), None);
        assert!(!has_log(&t, "Saving variable: TX:foo with value: "));
    }

    #[test]
    fn arithmetic_is_64_bit_on_the_integer_a_value_starts_with() {
        let ms = ModSecurity::new();
        let rules = rules();
        let r = rule(vec![]);
        let mut t = Transaction::new(&ms, &rules, None);
        let mut rm = RuleMessage::new(&r);
        for (previous, operand, subtract, expected) in [
            // Beyond 32 bits. (C++ computes in `int`: the first two wrap
            // around, and a value that does not fit an `int` counts as 0,
            // so the next two give 1 and 7.)
            ("2147483647", "1", false, "2147483648"),
            ("-2147483648", "1", true, "-2147483649"),
            ("2147483648", "1", false, "2147483649"),
            ("7", "-2147483649", false, "-2147483642"),
            // At the ends of the range.
            ("9223372036854775807", "1", false, "9223372036854775807"),
            ("-9223372036854775808", "1", true, "-9223372036854775808"),
            ("2suffix", " \t+3tail", false, "5"),
            ("2\0tail", "3", false, "5"),
            ("7", "", false, "7"),
            ("text", "4", false, "4"),
        ] {
            t.collections.tx.set(b"score", previous.as_bytes().to_vec());
            let operation = if subtract { Subtract(rts(operand)) } else { Add(rts(operand)) };
            setvar("score", operation).evaluate(&mut ActionContext::new(&mut t, &r, &mut rm));
            assert_eq!(t.collections.tx.get(b"score").unwrap(), expected.as_bytes());
        }
    }

    #[test]
    fn parsed_operations_expand_macros_before_updating() {
        let ms = ModSecurity::new();
        let mut rules = crate::rules_set::RulesSet::new();
        rules
            .load(
                r#"
            SecRuleEngine On
            SecAction "id:1,phase:1,pass,nolog,setvar:tx.key=score,setvar:tx.score=4"
            SecAction "id:2,phase:1,pass,nolog,setvar:tx.%{tx.key}=+%{tx.score},setvar:tx.score=-3"
            SecAction "id:3,phase:1,pass,nolog,setvar:tx.one,setvar:tx.empty=%{tx.missing},setvar:!tx.key"
        "#,
            )
            .unwrap();
        let mut t = Transaction::new(&ms, &rules, None);
        t.process_uri(b"/", b"GET", b"1.1");
        t.process_request_headers();
        for (key, expected) in
            [(&b"score"[..], Some(&b"5"[..])), (b"one", Some(&b"1"[..])), (b"empty", Some(&b""[..])), (b"key", None)]
        {
            assert_eq!(t.collections.tx.get(key), expected);
        }
    }

    /// Transactions on several threads add to one value of a persistent
    /// collection: none of the additions is lost (each reads and writes the
    /// value in one step of the storage).
    #[test]
    fn concurrent_additions_to_a_persistent_collection_are_all_counted() {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let ip = format!("setvar-{}-{now}", std::process::id());
        let ms = ModSecurity::new();
        let mut rules = crate::rules_set::RulesSet::new();
        rules
            .load(&format!(
                "SecRuleEngine On\n\
                 SecAction \"id:1,phase:1,pass,nolog,initcol:ip={ip}\"\n\
                 SecAction \"id:2,phase:1,pass,nolog,setvar:ip.hits=+1\"\n\
                 SecRule IP:hits \"@eq 401\" \"id:3,phase:1,deny,status:403,nolog\"\n"
            ))
            .unwrap();
        let request = || {
            let mut t = Transaction::new(&ms, &rules, None);
            t.process_uri(b"/", b"GET", b"1.1");
            t.process_request_headers();
            t.intervention().map(|i| i.status)
        };
        std::thread::scope(|s| {
            for _ in 0..8 {
                s.spawn(|| (0..50).for_each(|_| assert_eq!(request(), None)));
            }
        });
        // The 401st addition.
        assert_eq!(request(), Some(403));
    }
}
