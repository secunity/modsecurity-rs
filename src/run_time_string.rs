//! A string with `%{VAR}` macros, expanded per transaction.

use std::borrow::Cow;

use crate::rule::Rule;
use crate::transaction::Transaction;
use crate::variables::variable::Variable;

/// A piece of an interpolated string. The variable is boxed so that an
/// element stays small.
#[derive(Debug)]
enum Element {
    Text(Vec<u8>),
    Variable(Box<Variable>),
}

#[derive(Debug)]
enum Content {
    Literal(Vec<u8>),
    // Made only by `append_var`, so it always has a variable.
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

    /// A string made of a single literal.
    pub fn from_text(text: &str) -> Self {
        let mut r = Self::new();
        r.append_text(text);
        r
    }

    /// Appends literal text.
    pub fn append_text(&mut self, text: &str) {
        self.append_bytes(text.as_bytes());
    }

    /// Appends literal bytes.
    pub fn append_bytes(&mut self, text: &[u8]) {
        match &mut self.content {
            Content::Literal(literal) => literal.extend_from_slice(text),
            Content::Interpolated(elements) => match elements.last_mut() {
                Some(Element::Text(literal)) => literal.extend_from_slice(text),
                _ => elements.push(Element::Text(text.to_vec())),
            },
        }
    }

    /// Appends a macro: the variable is expanded at evaluation.
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

    /// The string in the transaction `t`: the literal text and, for each
    /// macro, the first value of its variable (nothing when it has none).
    /// The variables see `rule` only when it is a `SecRule`. A string
    /// without a macro is borrowed.
    pub fn expand(&self, t: &Transaction<'_>, rule: Option<&Rule>) -> Cow<'_, [u8]> {
        let elements = match &self.content {
            Content::Literal(text) => return Cow::Borrowed(text),
            Content::Interpolated(elements) => elements,
        };
        let rule = rule.filter(|r| r.is_sec_rule());
        let mut s = Vec::new();
        for element in elements {
            match element {
                Element::Text(text) => s.extend_from_slice(text),
                Element::Variable(variable) => {
                    let mut values = Vec::new();
                    variable.evaluate(t, rule, &mut values);
                    if let Some(first) = values.first() {
                        s.extend_from_slice(first.value());
                    }
                }
            }
        }
        Cow::Owned(s)
    }

    /// The string without a transaction: the literal text, the macros give
    /// nothing. What a rule set reads of a string by itself (a tag as
    /// written, a configuration value).
    pub fn text(&self) -> Cow<'_, [u8]> {
        match &self.content {
            Content::Literal(text) => Cow::Borrowed(text),
            Content::Interpolated(elements) => Cow::Owned(
                elements
                    .iter()
                    .filter_map(|e| match e {
                        Element::Text(text) => Some(text.as_slice()),
                        Element::Variable(_) => None,
                    })
                    .flatten()
                    .copied()
                    .collect(),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instance::ModSecurity;
    use crate::phases::Phases;
    use crate::rules_set::RulesSet;
    use crate::variables::{VariableSelector, new_variable};

    fn variable(name: &str, key: &str) -> Variable {
        new_variable(name, VariableSelector::DictElement(key.into())).unwrap()
    }

    #[test]
    fn literal_fragments_preserve_bytes_and_can_be_borrowed() {
        let mut string = RunTimeString::new();
        assert_eq!(*string.text(), *b"");
        string.append_text("a");
        string.append_bytes(b"\0\xff");
        string.append_text("");
        string.append_text("z");
        assert!(!string.contains_macro());
        assert!(matches!(string.text(), Cow::Borrowed(b"a\0\xffz")));
        let (ms, rules) = (ModSecurity::new(), RulesSet::new());
        let transaction = Transaction::new(&ms, &rules, None);
        assert!(matches!(string.expand(&transaction, None), Cow::Borrowed(b"a\0\xffz")));
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
        assert_eq!(*string.text(), *b"[]\xff");
        assert_eq!(*string.expand(&transaction, None), *b"[second]\xff");

        let mut only_variable = RunTimeString::new();
        only_variable.append_var(variable("ARGS", "missing"));
        assert!(only_variable.contains_macro());
        assert_eq!(*only_variable.text(), *b"");
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
        assert_eq!(*string.expand(&transaction, phase[0].as_rule()), *b"");
        assert_eq!(*string.expand(&transaction, phase[1].as_rule()), *b"20");
    }
}
