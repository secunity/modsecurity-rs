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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetVarOperation {
    /// Set variable to something
    SetOperation,
    /// read variable, sum predicate and set
    SumAndSetOperation,
    /// read variable, substract predicate and set
    SubstractAndSetOperation,
    /// set variable to 1
    SetToOneOperation,
    /// unset operation
    UnsetOperation,
}

#[derive(Debug)]
pub struct SetVar {
    pub operation: SetVarOperation,
    pub variable: Variable,
    pub string: Option<RunTimeString>,
}

impl SetVar {
    pub fn new(operation: SetVarOperation, variable: Variable, predicate: Option<RunTimeString>) -> Self {
        SetVar { operation, variable, string: predicate }
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
        let resolved_pre = match &self.string {
            Some(s) => s.evaluate_rule(Some(t), Some(rule)),
            None => Vec::new(),
        };

        // C++ `dynamic_cast`s the variable to the six `*_DynamicElement`
        // classes (TX, SESSION, IP, RESOURCE, GLOBAL, USER); the
        // `dynamic_*` hooks of `Variable` stand for that. Any other variable
        // only provides its name and cannot be stored to.
        let dynamic = self.variable.dynamic_name();
        let variable_name_expanded: Vec<u8> = match dynamic {
            Some(name) => name.evaluate_rule(Some(t), Some(rule)),
            None => self.variable.name().as_bytes().to_vec(),
        };

        let target_value: Vec<u8> = match self.operation {
            SetVarOperation::SetOperation => resolved_pre,
            SetVarOperation::SetToOneOperation => b"1".to_vec(),
            SetVarOperation::UnsetOperation => {
                if dynamic.is_some() {
                    self.variable.dynamic_del(t, &variable_name_expanded);
                }
                return;
            }
            SetVarOperation::SumAndSetOperation | SetVarOperation::SubstractAndSetOperation => {
                let pre = stoi_or_zero(&resolved_pre);

                let mut l = Vec::new();
                // C++ only forwards rules that are `RuleWithOperator`s.
                let rr = Some(rule).filter(|r| r.is_rule_with_operator());
                self.variable.evaluate(t, rr, &mut l);
                let value = l.first().map(|v| stoi_or_zero(v.value())).unwrap_or(0);

                // Signed overflow is undefined in C++; wrap.
                let r = if self.operation == SetVarOperation::SumAndSetOperation {
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

        if dynamic.is_some() {
            self.variable.dynamic_store_or_update_first(t, &variable_name_expanded, &target_value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::block::test_support::*;
    use crate::collection::Collection;
    use crate::modsecurity::ModSecurity;

    fn setvar(op: SetVarOperation, name: &str, pre: Option<&str>) -> SetVar {
        SetVar::new(op, tx(name), pre.map(rts))
    }

    #[test]
    fn operations() {
        let ms = ModSecurity::new();
        let rules = rules();
        let r = rule(vec![]);
        let mut t = Transaction::new(&ms, &rules, None);
        let mut rm = RuleMessage::new(&r);
        let tx = |t: &Transaction<'_>, k: &str| t.collections.tx_collection.resolve_first(k.as_bytes());

        setvar(SetVarOperation::SetOperation, "foo", Some("abc")).evaluate(&r, &mut t, &mut rm);
        assert_eq!(tx(&t, "foo"), Some(b"abc".to_vec()));
        assert!(has_log(&t, "Saving variable: TX:foo with value: abc"));

        setvar(SetVarOperation::SetToOneOperation, "one", None).evaluate(&r, &mut t, &mut rm);
        assert_eq!(tx(&t, "one"), Some(b"1".to_vec()));

        setvar(SetVarOperation::SumAndSetOperation, "score", Some("5")).evaluate(&r, &mut t, &mut rm);
        assert_eq!(tx(&t, "score"), Some(b"5".to_vec()));
        setvar(SetVarOperation::SumAndSetOperation, "score", Some("10")).evaluate(&r, &mut t, &mut rm);
        assert_eq!(tx(&t, "score"), Some(b"15".to_vec()));
        setvar(SetVarOperation::SubstractAndSetOperation, "score", Some("20")).evaluate(&r, &mut t, &mut rm);
        assert_eq!(tx(&t, "score"), Some(b"-5".to_vec()));
        assert!(has_log(&t, "Saving variable: TX:score with value: -5"));

        // Non numeric operands count as 0 (C++ `stoi` failures).
        setvar(SetVarOperation::SumAndSetOperation, "score", Some("x")).evaluate(&r, &mut t, &mut rm);
        assert_eq!(tx(&t, "score"), Some(b"-5".to_vec()));
        setvar(SetVarOperation::SumAndSetOperation, "foo", Some("3")).evaluate(&r, &mut t, &mut rm);
        assert_eq!(tx(&t, "foo"), Some(b"3".to_vec()));
        // Out of `int` range is a failure too.
        setvar(SetVarOperation::SumAndSetOperation, "big", Some("99999999999")).evaluate(&r, &mut t, &mut rm);
        assert_eq!(tx(&t, "big"), Some(b"0".to_vec()));

        setvar(SetVarOperation::UnsetOperation, "foo", None).evaluate(&r, &mut t, &mut rm);
        assert_eq!(tx(&t, "foo"), None);
        assert!(!has_log(&t, "Saving variable: TX:foo with value: "));
    }
}
