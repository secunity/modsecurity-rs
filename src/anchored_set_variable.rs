//! Port of `headers/modsecurity/anchored_set_variable.h` and
//! `src/anchored_set_variable.cc`.
//!
//! A multi valued transaction variable (e.g. `ARGS`), keyed case
//! insensitively. The C++ class *is* a
//! `std::unordered_multimap<std::string, VariableValue *, MyHash, MyEqual>`;
//! [`UnorderedMultimap`] reproduces that container's iteration order, which
//! decides the order targets are evaluated in.

use crate::transaction::Transaction;
use crate::utils::regex::Regex;
use crate::utils::unordered_multimap::UnorderedMultimap;
use crate::variable_origin::VariableOrigin;
use crate::variable_value::VariableValue;
use crate::variables::variable::KeyExclusions;

#[derive(Debug, Clone)]
pub struct AnchoredSetVariable {
    pub name: String,
    map: UnorderedMultimap<VariableValue>,
}

impl AnchoredSetVariable {
    pub fn new(name: &str) -> Self {
        AnchoredSetVariable { name: name.to_string(), map: UnorderedMultimap::with_reserve(10) }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Raw access in container order: `(key, value)`.
    pub fn iter(&self) -> impl Iterator<Item = (&[u8], &VariableValue)> {
        self.map.iter()
    }

    pub fn unset(&mut self) {
        self.map.clear();
    }

    /// `set(key, value, offset, len)`
    pub fn set_with_len(&mut self, key: &[u8], value: &[u8], offset: usize, len: usize) {
        let mut var = VariableValue::with_collection(self.name.as_bytes(), key, value);
        var.add_origin(VariableOrigin::new(len, offset));
        self.map.insert(key.to_vec(), var);
    }

    /// `set(key, value, offset)`
    pub fn set(&mut self, key: &[u8], value: &[u8], offset: usize) {
        let mut var = VariableValue::with_collection(self.name.as_bytes(), key, value);
        var.add_origin(VariableOrigin::new(value.len(), offset));
        self.map.insert(key.to_vec(), var);
    }

    /// `setCopy`
    pub fn set_copy(&mut self, key: &[u8], value: &[u8], offset: usize) {
        self.set(key, value, offset);
    }

    /// `resolve(l)`: note the C++ code inserts at the front of `l`, so the
    /// result is in reverse container order.
    pub fn resolve(&self, l: &mut Vec<VariableValue>) {
        for (_, v) in self.map.iter() {
            l.insert(0, v.clone());
        }
    }

    /// `resolve(l, ke)`
    pub fn resolve_with_exclusions(&self, l: &mut Vec<VariableValue>, ke: &KeyExclusions, t: Option<&Transaction<'_>>) {
        for (k, v) in self.map.iter() {
            if !ke.to_omit(k) {
                l.insert(0, v.clone());
            } else {
                crate::ms_dbg_opt!(t, 7, "Excluding key: {} from target value.", String::from_utf8_lossy(k));
            }
        }
    }

    /// `resolve(key, l)`
    pub fn resolve_key(&self, key: &[u8], l: &mut Vec<VariableValue>) {
        for (_, v) in self.map.equal_range(key) {
            l.push(v.clone());
        }
    }

    /// `resolveFirst(key)`
    pub fn resolve_first(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.map.find(key).map(|(_, v)| v.value().to_vec())
    }

    /// `resolveRegularExpression(r, l)`
    pub fn resolve_regular_expression(&self, r: &Regex, l: &mut Vec<VariableValue>) {
        for (k, v) in self.map.iter() {
            if r.search(k) <= 0 {
                continue;
            }
            l.insert(0, v.clone());
        }
    }

    /// `resolveRegularExpression(r, l, ke)`
    pub fn resolve_regular_expression_with_exclusions(
        &self,
        r: &Regex,
        l: &mut Vec<VariableValue>,
        ke: &KeyExclusions,
        t: Option<&Transaction<'_>>,
    ) {
        for (k, v) in self.map.iter() {
            if r.search(k) <= 0 {
                continue;
            }
            if !ke.to_omit(k) {
                l.insert(0, v.clone());
            } else {
                crate::ms_dbg_opt!(t, 7, "Excluding key: {} from target value.", String::from_utf8_lossy(k));
            }
        }
    }
}
