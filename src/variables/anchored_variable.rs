//! A single valued transaction variable (e.g. `REQUEST_METHOD`).
//!
//! The variable holds its name, value and origin; it has no reference to
//! the transaction that owns it.

use crate::variables::variable_origin::VariableOrigin;
use crate::variables::variable_value::VariableValue;

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

    /// Sets the value to `a` and adds an origin of `offset_len` bytes at
    /// `offset`.
    pub fn set_with_len(&mut self, a: &[u8], offset: usize, offset_len: usize) {
        self.offset = offset;
        self.value.clear();
        self.value.extend_from_slice(a);
        self.var.set_value(a);
        self.var.add_origin(VariableOrigin::new(offset_len, offset));
    }

    /// Sets the value to `a` and adds an origin covering it at `offset`.
    pub fn set(&mut self, a: &[u8], offset: usize) {
        self.offset = offset;
        self.value.clear();
        self.value.extend_from_slice(a);
        self.var.set_value(a);
        self.var.add_origin(VariableOrigin::new(self.value.len(), offset));
    }

    /// Appends the variable to `l` (nothing when it has no name).
    pub fn evaluate_into(&self, l: &mut Vec<VariableValue>) {
        if self.name.is_empty() {
            return;
        }
        // `var` holds the current value (kept in sync by set/unset), so
        // this only shares it.
        l.push(self.var.clone());
    }

    /// The current value.
    pub fn evaluate(&self) -> &[u8] {
        &self.value
    }

    #[cfg_attr(not(feature = "lua"), allow(dead_code))] // Used by the Lua engine.
    /// The current value, or `None` when it is empty.
    pub fn resolve_first(&self) -> Option<Vec<u8>> {
        if self.value.is_empty() {
            return None;
        }
        Some(self.value.clone())
    }
}
