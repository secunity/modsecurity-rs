//! A single valued transaction variable (e.g. `REQUEST_METHOD`).
//!
//! The variable holds its name, value and origin; it has no reference to
//! the transaction that owns it.

use std::cell::OnceCell;

use crate::variables::variable_origin::VariableOrigin;
use crate::variables::variable_value::VariableValue;

#[derive(Debug, Clone)]
pub struct SingleVariable {
    name: &'static str,
    /// Where the value starts in the request.
    offset: usize,
    /// The name (as the key), the value and where the value comes from;
    /// created when the variable is first set or read. Every transaction
    /// has all of these variables, and a request sets a few of them.
    var: OnceCell<VariableValue>,
}

impl SingleVariable {
    /// An empty variable; it allocates nothing until it is set or read.
    pub fn new(name: &'static str) -> Self {
        SingleVariable { name, offset: 0, var: OnceCell::new() }
    }

    /// The variable's value, created empty if it has none yet.
    fn var(&self) -> &VariableValue {
        self.var.get_or_init(|| VariableValue::new(self.name.as_bytes(), b""))
    }

    fn var_mut(&mut self) -> &mut VariableValue {
        self.var();
        self.var.get_mut().expect("initialized above")
    }

    /// The current value.
    pub fn value(&self) -> &[u8] {
        self.var.get().map_or(b"", VariableValue::value)
    }

    /// Where the current value starts in the request.
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// Empties the value; it has no origin then.
    pub fn unset(&mut self) {
        if let Some(var) = self.var.get_mut() {
            var.set_value(b"");
            var.clear_origins();
        }
    }

    /// Sets the value to `a`, found at `offset` in `offset_len` bytes of
    /// the request (its origin).
    pub fn set_with_len(&mut self, a: &[u8], offset: usize, offset_len: usize) {
        self.offset = offset;
        let origin = VariableOrigin::new(offset_len, offset);
        match self.var.get_mut() {
            Some(var) => {
                var.set_value(a);
                var.clear_origins();
                var.add_origin(origin);
            }
            None => {
                // The first value: built at once, in a buffer of its size.
                let mut var = VariableValue::new(self.name.as_bytes(), a);
                var.add_origin(origin);
                let _ = self.var.set(var);
            }
        }
    }

    /// Sets the value to `a`, found as is at `offset` in the request.
    pub fn set(&mut self, a: &[u8], offset: usize) {
        self.set_with_len(a, offset, a.len());
    }

    /// Sets the value to `a`, computed from more places of the request:
    /// `origins` are added to the ones the value has
    /// (`ARGS_COMBINED_SIZE` comes from every argument).
    pub fn set_adding_origins(&mut self, a: &[u8], origins: impl IntoIterator<Item = VariableOrigin>) {
        self.var_mut().set_value(a);
        for origin in origins {
            self.offset = origin.offset;
            self.var_mut().add_origin(origin);
        }
    }

    /// Appends the variable to `l`.
    pub fn evaluate_into(&self, l: &mut Vec<VariableValue>) {
        // Shares the value (a reference count).
        l.push(self.var().clone());
    }

    #[cfg_attr(not(feature = "lua"), allow(dead_code))] // Used by the Lua engine.
    /// The current value, or `None` when it is empty.
    pub fn resolve_first(&self) -> Option<Vec<u8>> {
        Some(self.value()).filter(|v| !v.is_empty()).map(<[u8]>::to_vec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A value set again replaces the one before, and its origin.
    #[test]
    fn set_replaces_value_and_origin() {
        let mut v = SingleVariable::new("MATCHED_VAR");
        for i in 0..1000 {
            v.set(format!("value {i}").as_bytes(), i);
        }
        let mut l = Vec::new();
        v.evaluate_into(&mut l);
        assert_eq!((l[0].key(), l[0].value()), (&b"MATCHED_VAR"[..], &b"value 999"[..]));
        assert_eq!(l[0].origin(), &[VariableOrigin::new(9, 999)]);
        assert_eq!((v.value(), v.offset()), (&b"value 999"[..], 999));

        v.set_with_len(b"abc", 5, 7);
        l.clear();
        v.evaluate_into(&mut l);
        assert_eq!(l[0].origin(), &[VariableOrigin::new(7, 5)]);

        v.unset();
        l.clear();
        v.evaluate_into(&mut l);
        assert_eq!((l[0].value(), l[0].origin().len()), (&b""[..], 0));
        assert_eq!(v.resolve_first(), None);
    }

    /// A rule that matches `MATCHED_VAR` reports where its current value
    /// is, not every value it had before.
    #[test]
    fn matched_var_has_the_origin_of_its_value() {
        use crate::instance::ModSecurity;
        use crate::rules_set::RulesSet;
        use crate::transaction::Transaction;
        let ms = ModSecurity::new();
        let mut rules = RulesSet::new();
        rules
            .load(
                "SecRuleEngine On\n\
                 SecRule ARGS \"@rx .\" \"id:1,phase:1,pass,log,chain\"\n\
                 SecRule MATCHED_VAR \"@rx .\" \"\"\n",
            )
            .unwrap();
        let mut t = Transaction::new(&ms, &rules, None);
        t.process_uri(b"/?a=1&b=2&c=3", b"GET", b"1.1");
        t.process_request_headers();
        let reference = String::from_utf8_lossy(t.rule_messages()[0].reference()).into_owned();
        // Three matches of ARGS, then one of MATCHED_VAR, set once per
        // match of ARGS: one origin.
        assert_eq!(reference, "o0,1v8,1o0,1v12,1o0,1v16,1o0,1v27,1");
    }

    /// A variable allocates nothing until it is set or read, and reads as
    /// the empty value of its name until then.
    #[test]
    fn created_when_first_set_or_read() {
        let mut v = SingleVariable::new("REQUEST_BODY");
        assert!(v.var.get().is_none());
        assert_eq!((v.value(), v.offset(), v.resolve_first()), (&b""[..], 0, None));
        v.unset();
        assert!(v.var.get().is_none());
        let mut l = Vec::new();
        v.evaluate_into(&mut l);
        assert_eq!((l[0].key(), l[0].value(), l[0].origin().len()), (&b"REQUEST_BODY"[..], &b""[..], 0));
        assert!(v.var.get().is_some());

        let mut w = SingleVariable::new("REQUEST_METHOD");
        w.set(b"GET", 0);
        assert_eq!(w.value(), b"GET");
    }

    /// A value computed from several places keeps all of them.
    #[test]
    fn set_adding_origins() {
        let mut v = SingleVariable::new("ARGS_COMBINED_SIZE");
        v.set_adding_origins(b"2", [VariableOrigin::new(1, 0), VariableOrigin::new(1, 2)]);
        v.set_adding_origins(b"4", [VariableOrigin::new(1, 4), VariableOrigin::new(1, 6)]);
        let mut l = Vec::new();
        v.evaluate_into(&mut l);
        assert_eq!(l[0].value(), b"4");
        assert_eq!(l[0].origin().len(), 4);
        assert_eq!(v.offset(), 6);
    }
}
