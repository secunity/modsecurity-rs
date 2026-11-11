//! Port of `src/run_time_string.h` / `src/run_time_string.cc`.
//!
//! A string with `%{VAR}` macros, expanded per transaction.

use std::borrow::Cow;

use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;
use crate::variables::variable::Variable;

/// `RunTimeElementHolder`: literal text or a variable.
#[derive(Debug)]
pub enum RunTimeElementHolder {
    String(Vec<u8>),
    Var(Box<dyn Variable>),
}

#[derive(Debug, Default)]
pub struct RunTimeString {
    pub contains_macro: bool,
    elements: Vec<RunTimeElementHolder>,
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
        self.elements.push(RunTimeElementHolder::String(text.as_bytes().to_vec()));
    }

    /// `appendText` with raw bytes.
    pub fn append_bytes(&mut self, text: &[u8]) {
        self.elements.push(RunTimeElementHolder::String(text.to_vec()));
    }

    /// `appendVar`
    pub fn append_var(&mut self, var: Box<dyn Variable>) {
        self.elements.push(RunTimeElementHolder::Var(var));
        self.contains_macro = true;
    }

    pub fn contains_macro(&self) -> bool {
        self.contains_macro
    }

    /// `evaluate(t, r)`: concatenates the literals and the first value of
    /// each variable. Without a transaction, variables expand to nothing.
    pub fn evaluate_rule(&self, t: Option<&Transaction<'_>>, r: Option<&RuleWithActions>) -> Vec<u8> {
        let mut s = Vec::new();
        for z in &self.elements {
            match z {
                // C++ checks `m_string.size() > 0` first; an empty literal
                // contributes nothing either way.
                RunTimeElementHolder::String(st) => s.extend_from_slice(st),
                RunTimeElementHolder::Var(v) => {
                    if let Some(t) = t {
                        let mut l = Vec::new();
                        // The C++ code only forwards rules that are
                        // RuleWithOperator.
                        let rr = r.filter(|r| r.is_rule_with_operator());
                        v.evaluate(t, rr, &mut l);
                        if let Some(first) = l.first() {
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
        match self.elements.as_slice() {
            [] => Cow::Borrowed(b""),
            [RunTimeElementHolder::String(st)] => Cow::Borrowed(st),
            _ => Cow::Owned(self.evaluate(t)),
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
