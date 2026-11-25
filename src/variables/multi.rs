//! A multi valued transaction variable (e.g. `ARGS`), keyed case
//! insensitively.
//!
//! The entries are kept in an [`UnorderedMultimap`], which reproduces the
//! iteration order of libstdc++'s `std::unordered_multimap` as the C++
//! library uses it. That order decides the order targets are evaluated in,
//! and it is kept because the upstream tests depend on it.

use crate::transaction::Transaction;
use crate::variables::variable::KeyExclusions;
use crate::variables::variable_origin::VariableOrigin;
use crate::variables::variable_value::{VariableValue, move_to_front_reversed};
use modsecurity_compat::unordered_multimap::UnorderedMultimap;
use modsecurity_native::regex::Regex;

/// An entry: the value and, for a variable with [`Names`] (`ARGS`,
/// `ARGS_GET`, `ARGS_POST`), its key as a value of the names variable,
/// built once here instead of on every resolution of the names.
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
            Pick::Name => self.name.as_ref().expect("a variable with names"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MultiVariable {
    pub name: &'static str,
    map: UnorderedMultimap<Entry>,
    /// The name of the variable of its keys (`ARGS_NAMES` of `ARGS`), if
    /// it has one.
    names_collection: Option<&'static str>,
}

impl MultiVariable {
    /// An empty variable. It allocates nothing until a value is added:
    /// every transaction creates all of them, and a request fills a few.
    pub fn new(name: &'static str) -> Self {
        MultiVariable { name, map: UnorderedMultimap::with_reserve(10), names_collection: None }
    }

    /// A variable whose keys are also the variable `names` (e.g. `ARGS`
    /// and `ARGS_NAMES`), see [`Self::names`].
    pub fn with_names(name: &'static str, names: &'static str) -> Self {
        MultiVariable { names_collection: Some(names), ..Self::new(name) }
    }

    /// The keys as a variable of their own (`ARGS_NAMES` of `ARGS`). Only
    /// a variable made [`Self::with_names`] has them.
    pub fn names(&self) -> Names<'_> {
        assert!(self.names_collection.is_some(), "{} has no names variable", self.name);
        Names { of: self }
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

    /// Adds every value to `l`. The values are inserted at the front of
    /// `l`, so they come out in reverse container order.
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

    /// [`Self::resolve`] restricted to the keys that match `r`, skipping the
    /// keys excluded by `ke`.
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
            if !r.is_match(k) {
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
}

/// The keys of a [`MultiVariable`] as a variable of their own: `ARGS_NAMES`
/// is the keys of `ARGS`. Each value has the key as its key and value, and
/// its origin points at the key. The resolutions are the variable's, with
/// these values.
#[derive(Clone, Copy)]
pub struct Names<'v> {
    of: &'v MultiVariable,
}

impl Names<'_> {
    #[cfg_attr(not(feature = "lua"), allow(dead_code))] // Used by the Lua engine.
    pub fn resolve(&self, l: &mut Vec<VariableValue>) {
        self.of.resolve_pick(Pick::Name, l)
    }

    pub fn resolve_with_exclusions(&self, l: &mut Vec<VariableValue>, ke: &KeyExclusions, t: Option<&Transaction<'_>>) {
        self.of.resolve_with_exclusions_pick(Pick::Name, l, ke, t)
    }

    pub fn resolve_key(&self, key: &[u8], l: &mut Vec<VariableValue>) {
        self.of.resolve_key_pick(Pick::Name, key, l)
    }

    pub fn resolve_regular_expression_with_exclusions(
        &self,
        r: &Regex,
        l: &mut Vec<VariableValue>,
        ke: &KeyExclusions,
        t: Option<&Transaction<'_>>,
    ) {
        self.of.resolve_regular_expression_with_exclusions_pick(Pick::Name, r, l, ke, t)
    }
}

/// The value of the names variable `name` for the value `v`: `v`'s key as
/// key and value, with the origins moved to point at the key.
fn translate(name: &str, v: &VariableValue) -> VariableValue {
    let mut nv = VariableValue::with_collection(name.as_bytes(), v.key(), v.key());
    nv.reserve_origin(v.origin().len());
    for o in v.origin() {
        nv.add_origin(VariableOrigin::new(v.key().len(), o.offset.wrapping_sub(v.key().len()).wrapping_sub(1)));
    }
    nv
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each resolution of the names is the variable's resolution with every
    /// value translated.
    #[test]
    fn names_are_the_translated_values() {
        let mut args = MultiVariable::with_names("ARGS", "ARGS_NAMES");
        for (k, v, off) in [(&b"a"[..], &b"1"[..], 3), (b"b", b"22", 0), (b"a", b"333", 9), (b"", b"x", 1)] {
            args.set(k, v, off);
        }
        let names = args.names();
        let r = Regex::new("^a");
        let ke = KeyExclusions::default();
        let run = |f: &dyn Fn(&mut Vec<VariableValue>)| {
            let mut l = Vec::new();
            f(&mut l);
            l
        };
        let translated = |l: Vec<VariableValue>| l.iter().map(|v| translate("ARGS_NAMES", v)).collect::<Vec<_>>();

        let all = run(&|l| names.resolve(l));
        assert_eq!(all.len(), 4);
        assert!(all.iter().all(|v| v.collection() == b"ARGS_NAMES" && v.key() == v.value()));
        assert_eq!(all, translated(run(&|l| args.resolve(l))));
        assert_eq!(
            run(&|l| names.resolve_with_exclusions(l, &ke, None)),
            translated(run(&|l| args.resolve_with_exclusions(l, &ke, None)))
        );
        assert_eq!(run(&|l| names.resolve_key(b"a", l)), translated(run(&|l| args.resolve_key(b"a", l))));
        assert_eq!(
            run(&|l| names.resolve_regular_expression_with_exclusions(&r, l, &ke, None)),
            translated(run(&|l| args.resolve_regular_expression_with_exclusions(&r, l, &ke, None)))
        );
    }

    #[test]
    #[should_panic(expected = "FILES has no names variable")]
    fn only_a_variable_with_names_has_them() {
        MultiVariable::new("FILES").names();
    }
}
