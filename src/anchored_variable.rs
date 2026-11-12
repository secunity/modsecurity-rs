//! Port of `headers/modsecurity/anchored_variable.h` and
//! `src/anchored_variable.cc`.
//!
//! A single valued transaction variable (e.g. `REQUEST_METHOD`). The C++
//! class kept a back pointer to its transaction that was never used for
//! anything but construction; it is not needed here.

use crate::variable_origin::VariableOrigin;
use crate::variable_value::VariableValue;

#[derive(Debug, Clone)]
pub struct AnchoredVariable {
    pub offset: usize,
    pub name: String,
    /// Written only through `set*`/`unset`, which keep `var` in sync.
    pub value: Vec<u8>,
    var: VariableValue,
}

impl AnchoredVariable {
    pub fn new(name: &str) -> Self {
        AnchoredVariable {
            offset: 0,
            name: name.to_string(),
            value: Vec::new(),
            var: VariableValue::new(name.as_bytes(), b""),
        }
    }

    pub fn unset(&mut self) {
        self.value.clear();
        self.var.set_value(b"");
    }

    /// `set(a, offset, offsetLen)`
    pub fn set_with_len(&mut self, a: &[u8], offset: usize, offset_len: usize) {
        self.offset = offset;
        self.value.clear();
        self.value.extend_from_slice(a);
        self.var.set_value(a);
        self.var.add_origin(VariableOrigin::new(offset_len, offset));
    }

    /// `set(a, offset)`
    pub fn set(&mut self, a: &[u8], offset: usize) {
        self.offset = offset;
        self.value.clear();
        self.value.extend_from_slice(a);
        self.var.set_value(a);
        self.var.add_origin(VariableOrigin::new(self.value.len(), offset));
    }

    /// `evaluate(std::vector<const VariableValue *> *l)`
    pub fn evaluate_into(&self, l: &mut Vec<VariableValue>) {
        if self.name.is_empty() {
            return;
        }
        // `var` holds the current value (kept in sync by set/unset), so
        // this only shares it (C++: `m_var.m_value.assign(m_value)`).
        l.push(self.var.clone());
    }

    /// `std::string *evaluate()`
    pub fn evaluate(&self) -> &[u8] {
        &self.value
    }

    /// `resolveFirst`
    pub fn resolve_first(&self) -> Option<Vec<u8>> {
        if self.value.is_empty() {
            return None;
        }
        Some(self.value.clone())
    }
}
