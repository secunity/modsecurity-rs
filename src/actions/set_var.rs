//! Port of `src/actions/set_var.cc`, `src/actions/set_var.h`.
//!
//! `setvar:tx.name=value`, `setvar:tx.name=+N`, `setvar:tx.name=-N`,
//! `setvar:tx.name`, `setvar:!tx.name` — creates, updates or removes a
//! variable of the TX or of a persistent collection.

use crate::actions::action::Action;
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;
use crate::utils::string::{lossy, stoi};
use crate::variables::variable::Variable;

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

/// `std::stoi` where any failure (no digits, out of `int` range) is 0.
fn stoi_or_zero(s: &[u8]) -> i32 {
    stoi(s).and_then(|v| i32::try_from(v).ok()).unwrap_or(0)
}

impl Action for SetVar {
    fn name(&self) -> &str {
        "setvar"
    }

    fn evaluate(&self, rule: &RuleWithActions, t: &mut Transaction<'_>, _rm: &mut RuleMessage<'_>) {
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
                let pre = stoi_or_zero(&resolved_pre);

                let mut l = Vec::new();
                // C++ only forwards rules that are `RuleWithOperator`s.
                let rr = Some(rule).filter(|r| r.is_rule_with_operator());
                self.variable.evaluate(t, rr, &mut l);
                let value = l.first().map(|v| stoi_or_zero(v.value())).unwrap_or(0);

                // Signed overflow is undefined in C++; wrap.
                let r = if matches!(self.operation, SetVarOperation::Add(_)) {
                    value.wrapping_add(pre)
                } else {
                    value.wrapping_sub(pre)
                };
                r.to_string().into_bytes()
            }
        };

        crate::ms_dbg_a!(
            t,
            8,
            "Saving variable: {}:{} with value: {}",
            self.variable.collection_name(),
            lossy(&variable_name_expanded),
            lossy(&target_value)
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
    use crate::modsecurity::ModSecurity;

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

        setvar("foo", Set(rts("abc"))).evaluate(&r, &mut t, &mut rm);
        assert_eq!(tx(&t, "foo"), Some(b"abc".to_vec()));
        assert!(has_log(&t, "Saving variable: TX:foo with value: abc"));

        setvar("one", SetToOne).evaluate(&r, &mut t, &mut rm);
        assert_eq!(tx(&t, "one"), Some(b"1".to_vec()));

        setvar("score", Add(rts("5"))).evaluate(&r, &mut t, &mut rm);
        assert_eq!(tx(&t, "score"), Some(b"5".to_vec()));
        setvar("score", Add(rts("10"))).evaluate(&r, &mut t, &mut rm);
        assert_eq!(tx(&t, "score"), Some(b"15".to_vec()));
        setvar("score", Subtract(rts("20"))).evaluate(&r, &mut t, &mut rm);
        assert_eq!(tx(&t, "score"), Some(b"-5".to_vec()));
        assert!(has_log(&t, "Saving variable: TX:score with value: -5"));

        // Non numeric operands count as 0 (C++ `stoi` failures).
        setvar("score", Add(rts("x"))).evaluate(&r, &mut t, &mut rm);
        assert_eq!(tx(&t, "score"), Some(b"-5".to_vec()));
        setvar("foo", Add(rts("3"))).evaluate(&r, &mut t, &mut rm);
        assert_eq!(tx(&t, "foo"), Some(b"3".to_vec()));
        // Out of `int` range is a failure too.
        setvar("big", Add(rts("99999999999"))).evaluate(&r, &mut t, &mut rm);
        assert_eq!(tx(&t, "big"), Some(b"0".to_vec()));

        setvar("foo", Unset).evaluate(&r, &mut t, &mut rm);
        assert_eq!(tx(&t, "foo"), None);
        assert!(!has_log(&t, "Saving variable: TX:foo with value: "));
    }

    #[test]
    fn arithmetic_keeps_prefix_parsing_and_wrapping() {
        let ms = ModSecurity::new();
        let rules = rules();
        let r = rule(vec![]);
        let mut t = Transaction::new(&ms, &rules, None);
        let mut rm = RuleMessage::new(&r);
        for (previous, operand, subtract, expected) in [
            ("2147483647", "1", false, "-2147483648"),
            ("-2147483648", "1", true, "2147483647"),
            ("2suffix", " \t+3tail", false, "5"),
            ("2\0tail", "3", false, "5"),
            ("2147483648", "1", false, "1"),
            ("7", "-2147483649", false, "7"),
            ("7", "", false, "7"),
        ] {
            t.collections.tx.set(b"score", previous.as_bytes().to_vec());
            let operation = if subtract { Subtract(rts(operand)) } else { Add(rts(operand)) };
            setvar("score", operation).evaluate(&r, &mut t, &mut rm);
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
}
