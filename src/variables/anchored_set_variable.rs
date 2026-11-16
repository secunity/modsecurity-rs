//! A multi valued transaction variable (e.g. `ARGS`), keyed case
//! insensitively.
//!
//! The C++ class *is* a
//! `std::unordered_multimap<std::string, VariableValue *, MyHash, MyEqual>`;
//! [`UnorderedMultimap`] reproduces that container's iteration order, which
//! decides the order targets are evaluated in.

use crate::transaction::Transaction;
use crate::utils::regex::Regex;
use crate::utils::unordered_multimap::UnorderedMultimap;
use crate::variables::anchored_set_variable_translation_proxy::translate;
use crate::variables::variable::KeyExclusions;
use crate::variables::variable_origin::VariableOrigin;
use crate::variables::variable_value::{VariableValue, move_to_front_reversed};

/// An entry: the value and, for collections with a `*_NAMES` translation
/// proxy (`ARGS`, `ARGS_GET`, `ARGS_POST`), its key as a value of that
/// proxy, built once here instead of on every resolution of the proxy.
#[derive(Debug, Clone)]
struct Entry {
    value: VariableValue,
    name: Option<VariableValue>,
}

/// Which variable of an [`Entry`] a resolution returns.
#[derive(Clone, Copy)]
enum Pick {
    Value,
    Name,
}

impl Entry {
    fn get(&self, pick: Pick) -> &VariableValue {
        match pick {
            Pick::Value => &self.value,
            Pick::Name => self.name.as_ref().expect("names_collection is set"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AnchoredSetVariable {
    pub name: String,
    map: UnorderedMultimap<Entry>,
    /// The collection name of the translation proxy over this variable.
    names_collection: Option<String>,
}

impl AnchoredSetVariable {
    pub fn new(name: &str) -> Self {
        AnchoredSetVariable { name: name.to_string(), map: UnorderedMultimap::with_reserve(10), names_collection: None }
    }

    /// A variable with a translation proxy named `names` (e.g. `ARGS` and
    /// `ARGS_NAMES`).
    pub fn with_names(name: &str, names: &str) -> Self {
        AnchoredSetVariable { names_collection: Some(names.to_string()), ..Self::new(name) }
    }

    /// Whether the entries carry values of the translation proxy `names`
    /// (see [`Self::with_names`]).
    pub fn has_names(&self, names: &str) -> bool {
        self.names_collection.as_deref() == Some(names)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn unset(&mut self) {
        self.map.clear();
    }

    fn insert(&mut self, key: &[u8], value: VariableValue) {
        let name = self.names_collection.as_ref().map(|n| translate(n, &value));
        self.map.insert(key.to_vec(), Entry { value, name });
    }

    /// Adds a value under `key`; its origin is `len` bytes at `offset`.
    pub fn set_with_len(&mut self, key: &[u8], value: &[u8], offset: usize, len: usize) {
        let mut var = VariableValue::with_collection(self.name.as_bytes(), key, value);
        var.add_origin(VariableOrigin::new(len, offset));
        self.insert(key, var);
    }

    /// Raw access in container order: `(key, value)`.
    #[cfg(test)]
    pub fn iter(&self) -> impl Iterator<Item = (&[u8], &VariableValue)> {
        self.map.iter().map(|(k, e)| (k, &e.value))
    }

    /// Adds a value under `key`; its origin is the whole value at
    /// `offset`.
    pub fn set(&mut self, key: &[u8], value: &[u8], offset: usize) {
        let mut var = VariableValue::with_collection(self.name.as_bytes(), key, value);
        var.add_origin(VariableOrigin::new(value.len(), offset));
        self.insert(key, var);
    }

    /// Adds every value to `l`. As in C++, the values are inserted at the
    /// front of `l`, so they come out in reverse container order.
    pub fn resolve(&self, l: &mut Vec<VariableValue>) {
        self.resolve_pick(Pick::Value, l)
    }

    fn resolve_pick(&self, pick: Pick, l: &mut Vec<VariableValue>) {
        let start = l.len();
        l.extend(self.map.iter().map(|(_, e)| e.get(pick).clone()));
        move_to_front_reversed(l, start);
    }

    /// [`Self::resolve`], skipping the keys excluded by `ke`.
    pub fn resolve_with_exclusions(&self, l: &mut Vec<VariableValue>, ke: &KeyExclusions, t: Option<&Transaction<'_>>) {
        self.resolve_with_exclusions_pick(Pick::Value, l, ke, t)
    }

    fn resolve_with_exclusions_pick(
        &self,
        pick: Pick,
        l: &mut Vec<VariableValue>,
        ke: &KeyExclusions,
        t: Option<&Transaction<'_>>,
    ) {
        let start = l.len();
        for (k, e) in self.map.iter() {
            if !ke.to_omit(k) {
                l.push(e.get(pick).clone());
            } else {
                crate::ms_dbg_opt!(t, 7, "Excluding key: {} from target value.", String::from_utf8_lossy(k));
            }
        }
        move_to_front_reversed(l, start);
    }

    /// Appends the values stored under `key` to `l`.
    pub fn resolve_key(&self, key: &[u8], l: &mut Vec<VariableValue>) {
        self.resolve_key_pick(Pick::Value, key, l)
    }

    fn resolve_key_pick(&self, pick: Pick, key: &[u8], l: &mut Vec<VariableValue>) {
        for (_, e) in self.map.equal_range(key) {
            l.push(e.get(pick).clone());
        }
    }

    /// The first value stored under `key`, if any.
    pub fn resolve_first(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.map.find(key).map(|(_, e)| e.value.value().to_vec())
    }

    /// [`Self::resolve`] restricted to the keys that match `r`, skipping the keys excluded
    /// by `ke`.
    pub fn resolve_regular_expression_with_exclusions(
        &self,
        r: &Regex,
        l: &mut Vec<VariableValue>,
        ke: &KeyExclusions,
        t: Option<&Transaction<'_>>,
    ) {
        self.resolve_regular_expression_with_exclusions_pick(Pick::Value, r, l, ke, t)
    }

    fn resolve_regular_expression_with_exclusions_pick(
        &self,
        pick: Pick,
        r: &Regex,
        l: &mut Vec<VariableValue>,
        ke: &KeyExclusions,
        t: Option<&Transaction<'_>>,
    ) {
        let start = l.len();
        for (k, e) in self.map.iter() {
            if r.search(k) <= 0 {
                continue;
            }
            if !ke.to_omit(k) {
                l.push(e.get(pick).clone());
            } else {
                crate::ms_dbg_opt!(t, 7, "Excluding key: {} from target value.", String::from_utf8_lossy(k));
            }
        }
        move_to_front_reversed(l, start);
    }

    #[cfg_attr(not(feature = "lua"), allow(dead_code))] // Used by the Lua engine.
    /// The translation proxy's resolutions: the same as the ones above
    /// with the entries' name values (only for [`Self::has_names`]).
    pub(crate) fn resolve_names(&self, l: &mut Vec<VariableValue>) {
        self.resolve_pick(Pick::Name, l)
    }

    pub(crate) fn resolve_names_with_exclusions(
        &self,
        l: &mut Vec<VariableValue>,
        ke: &KeyExclusions,
        t: Option<&Transaction<'_>>,
    ) {
        self.resolve_with_exclusions_pick(Pick::Name, l, ke, t)
    }

    pub(crate) fn resolve_names_key(&self, key: &[u8], l: &mut Vec<VariableValue>) {
        self.resolve_key_pick(Pick::Name, key, l)
    }

    pub(crate) fn resolve_names_regular_expression_with_exclusions(
        &self,
        r: &Regex,
        l: &mut Vec<VariableValue>,
        ke: &KeyExclusions,
        t: Option<&Transaction<'_>>,
    ) {
        self.resolve_regular_expression_with_exclusions_pick(Pick::Name, r, l, ke, t)
    }
}
