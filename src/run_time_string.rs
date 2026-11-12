//! Port of `src/run_time_string.h` / `src/run_time_string.cc`.
//!
//! A string with `%{VAR}` macros, expanded per transaction.

use std::borrow::Cow;

use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;
use crate::variables::variable::Variable;

/// Interpolated strings keep variables boxed so literal fragments stay small.
#[derive(Debug)]
enum Element {
    Text(Vec<u8>),
    Variable(Box<Variable>),
}

#[derive(Debug)]
enum Content {
    Literal(Vec<u8>),
    // Constructed only by append_var, so always contains a variable.
    Interpolated(Vec<Element>),
}

#[derive(Debug)]
pub struct RunTimeString {
    content: Content,
}

impl Default for RunTimeString {
    fn default() -> Self {
        Self { content: Content::Literal(Vec::new()) }
    }
}

impl RunTimeString {
    pub fn new() -> Self {
        Self::default()
    }

    /// Convenience: a string made of a single literal.
    pub fn from_text(text: &str) -> Self {
        let mut r = Self::new();
        r.append_text(text);
        r
    }

    /// `appendText`
    pub fn append_text(&mut self, text: &str) {
        self.append_bytes(text.as_bytes());
    }

    /// `appendText` with raw bytes.
    pub fn append_bytes(&mut self, text: &[u8]) {
        match &mut self.content {
            Content::Literal(literal) => literal.extend_from_slice(text),
            Content::Interpolated(elements) => match elements.last_mut() {
                Some(Element::Text(literal)) => literal.extend_from_slice(text),
                _ => elements.push(Element::Text(text.to_vec())),
            },
        }
    }

    /// `appendVar`
    pub fn append_var(&mut self, var: Variable) {
        let variable = Element::Variable(Box::new(var));
        match &mut self.content {
            Content::Literal(text) => {
                let prefix = std::mem::take(text);
                self.content = Content::Interpolated(vec![Element::Text(prefix), variable]);
            }
            Content::Interpolated(elements) => elements.push(variable),
        }
    }

    pub fn contains_macro(&self) -> bool {
        matches!(self.content, Content::Interpolated(_))
    }

    /// `evaluate(t, r)`: concatenates the literals and the first value of
    /// each variable. Without a transaction, variables expand to nothing.
    pub fn evaluate_rule(&self, t: Option<&Transaction<'_>>, r: Option<&RuleWithActions>) -> Vec<u8> {
        let elements = match &self.content {
            Content::Literal(text) => return text.clone(),
            Content::Interpolated(elements) => elements,
        };
        // C++ only forwards operator rules to macro resolution.
        let rule = r.filter(|r| r.is_rule_with_operator());
        let mut s = Vec::new();
        for element in elements {
            match element {
                Element::Text(text) => s.extend_from_slice(text),
                Element::Variable(variable) => {
                    if let Some(t) = t {
                        let mut values = Vec::new();
                        variable.evaluate(t, rule, &mut values);
                        if let Some(first) = values.first() {
                            s.extend_from_slice(first.value());
                        }
                    }
                }
            }
        }
        s
    }

    /// `evaluate(t)` without copying when the string is plain text (no
    /// macro): for hot comparisons such as `containsTag`.
    pub fn evaluate_cow(&self, t: Option<&Transaction<'_>>) -> Cow<'_, [u8]> {
        match &self.content {
            Content::Literal(text) => Cow::Borrowed(text),
            Content::Interpolated(_) => Cow::Owned(self.evaluate(t)),
        }
    }

    /// `evaluate(t)`
    pub fn evaluate(&self, t: Option<&Transaction<'_>>) -> Vec<u8> {
        self.evaluate_rule(t, None)
    }

    /// `evaluate()` (no transaction).
    pub fn evaluate_static(&self) -> Vec<u8> {
        self.evaluate(None)
    }

    /// `evaluate()` as a (lossy) UTF-8 string, for configuration values.
    pub fn evaluate_static_string(&self) -> String {
        String::from_utf8_lossy(&self.evaluate_static()).into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modsecurity::{ModSecurity, Phases};
    use crate::rules_set::RulesSet;
    use crate::variables::{VariableSelector, new_variable};

    fn variable(name: &str, key: &str) -> Variable {
        new_variable(name, VariableSelector::DictElement(key.into())).unwrap()
    }

    #[test]
    fn literal_fragments_preserve_bytes_and_can_be_borrowed() {
        let mut string = RunTimeString::new();
        assert_eq!(string.evaluate_static(), b"");
        string.append_text("a");
        string.append_bytes(b"\0\xff");
        string.append_text("");
        string.append_text("z");
        assert!(!string.contains_macro());
        assert_eq!(string.evaluate_static(), b"a\0\xffz");
        assert!(matches!(string.evaluate_cow(None), Cow::Borrowed(b"a\0\xffz")));
    }

    #[test]
    fn interpolation_keeps_first_value_missing_values_and_literal_order() {
        let ms = ModSecurity::new();
        let rules = RulesSet::new();
        let mut transaction = Transaction::new(&ms, &rules, None);
        transaction.vars.args.set(b"key", b"first", 0);
        transaction.vars.args.set(b"key", b"second", 0);

        let mut string = RunTimeString::from_text("[");
        string.append_var(variable("ARGS", "key"));
        string.append_var(variable("ARGS", "missing"));
        string.append_text("]");
        string.append_bytes(b"\xff");
        assert!(string.contains_macro());
        assert_eq!(string.evaluate_static(), b"[]\xff");
        assert_eq!(string.evaluate(Some(&transaction)), b"[second]\xff");
        assert_eq!(string.evaluate_cow(Some(&transaction)).as_ref(), b"[second]\xff");

        let mut only_variable = RunTimeString::new();
        only_variable.append_var(variable("ARGS", "missing"));
        assert!(only_variable.contains_macro());
        assert_eq!(only_variable.evaluate_static(), b"");
    }

    #[test]
    fn rule_macros_only_receive_operator_rules() {
        let ms = ModSecurity::new();
        let mut rules = RulesSet::new();
        rules
            .load(
                r#"
            SecAction "id:10,phase:1,pass"
            SecRule ARGS "@rx x" "id:20,phase:1,pass"
        "#,
            )
            .unwrap();
        let transaction = Transaction::new(&ms, &rules, None);
        let mut string = RunTimeString::new();
        string.append_var(variable("RULE", "id"));
        let phase = rules.rules_set_phases.for_phase(Phases::RequestHeaders);
        assert_eq!(string.evaluate_rule(Some(&transaction), phase[0].as_rule_with_actions()), b"");
        assert_eq!(string.evaluate_rule(Some(&transaction), phase[1].as_rule_with_actions()), b"20");
    }
}
