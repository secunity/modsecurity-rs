//! Port of `headers/modsecurity/anchored_set_variable_translation_proxy.h`.
//!
//! Exposes the *names* of an [`AnchoredSetVariable`] as a collection of its
//! own (`ARGS_NAMES` over `ARGS`, ...). In C++ the proxy held a pointer to
//! its source; here the source is passed in by the caller (both live in the
//! same transaction).

use crate::anchored_set_variable::AnchoredSetVariable;
use crate::transaction::Transaction;
use crate::utils::regex::Regex;
use crate::variable_origin::VariableOrigin;
use crate::variable_value::VariableValue;
use crate::variables::variable::KeyExclusions;

/// `m_translate` of one value: a value of collection `name` whose key and
/// value are `v`'s key, with the origins moved to point at the key.
pub(crate) fn translate(name: &str, v: &VariableValue) -> VariableValue {
    let mut nv = VariableValue::with_collection(name.as_bytes(), v.key(), v.key());
    nv.reserve_origin(v.origin().len());
    for o in v.origin() {
        nv.add_origin(VariableOrigin::new(v.key().len(), o.offset.wrapping_sub(v.key().len()).wrapping_sub(1)));
    }
    nv
}

#[derive(Debug, Clone)]
pub struct AnchoredSetVariableTranslationProxy {
    pub name: String,
}

impl AnchoredSetVariableTranslationProxy {
    pub fn new(name: &str) -> Self {
        AnchoredSetVariableTranslationProxy { name: name.to_string() }
    }

    /// `m_translate`: replaces each value (of the whole list, as in C++) by one whose key and value are the
    /// original key, adjusting the origins to point at the key.
    fn translate(&self, l: &mut [VariableValue]) {
        for v in l.iter_mut() {
            *v = translate(&self.name, v);
        }
    }

    /// Whether `fount`'s stored name values can be used: they are the
    /// translation of its entries, and `l` holds nothing else that the C++
    /// translation of the whole list would rewrite.
    fn use_stored_names(&self, fount: &AnchoredSetVariable, l: &[VariableValue]) -> bool {
        l.is_empty() && fount.has_names(&self.name)
    }

    pub fn resolve(&self, fount: &AnchoredSetVariable, l: &mut Vec<VariableValue>) {
        if self.use_stored_names(fount, l) {
            return fount.resolve_names(l);
        }
        fount.resolve(l);
        self.translate(l);
    }

    pub fn resolve_with_exclusions(
        &self,
        fount: &AnchoredSetVariable,
        l: &mut Vec<VariableValue>,
        ke: &KeyExclusions,
        t: Option<&Transaction<'_>>,
    ) {
        if self.use_stored_names(fount, l) {
            return fount.resolve_names_with_exclusions(l, ke, t);
        }
        fount.resolve_with_exclusions(l, ke, t);
        self.translate(l);
    }

    pub fn resolve_key(&self, fount: &AnchoredSetVariable, key: &[u8], l: &mut Vec<VariableValue>) {
        if self.use_stored_names(fount, l) {
            return fount.resolve_names_key(key, l);
        }
        fount.resolve_key(key, l);
        self.translate(l);
    }

    pub fn resolve_regular_expression(&self, fount: &AnchoredSetVariable, r: &Regex, l: &mut Vec<VariableValue>) {
        if self.use_stored_names(fount, l) {
            return fount.resolve_names_regular_expression(r, l);
        }
        fount.resolve_regular_expression(r, l);
        self.translate(l);
    }

    pub fn resolve_regular_expression_with_exclusions(
        &self,
        fount: &AnchoredSetVariable,
        r: &Regex,
        l: &mut Vec<VariableValue>,
        ke: &KeyExclusions,
        t: Option<&Transaction<'_>>,
    ) {
        if self.use_stored_names(fount, l) {
            return fount.resolve_names_regular_expression_with_exclusions(r, l, ke, t);
        }
        fount.resolve_regular_expression_with_exclusions(r, l, ke, t);
        self.translate(l);
    }

    /// `resolveFirst(key)`: note the C++ implementation ignores `key` and
    /// returns the first name.
    pub fn resolve_first(&self, fount: &AnchoredSetVariable, _key: &[u8]) -> Option<Vec<u8>> {
        let mut l = Vec::new();
        self.resolve(fount, &mut l);
        l.first().map(|v| v.value().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The values stored at `set` time are exactly what translating the
    /// fount's resolution gives, for every resolution; with a non-empty list
    /// the whole list is still translated (C++ behaviour).
    #[test]
    fn stored_names_match_translation() {
        let proxy = AnchoredSetVariableTranslationProxy::new("ARGS_NAMES");
        let mut with = AnchoredSetVariable::with_names("ARGS", "ARGS_NAMES");
        let mut without = AnchoredSetVariable::new("ARGS");
        for (k, v, off) in [(&b"a"[..], &b"1"[..], 3), (b"b", b"22", 0), (b"a", b"333", 9), (b"", b"x", 1)] {
            with.set(k, v, off);
            without.set(k, v, off);
        }
        let r = Regex::new("^a");
        let ke = KeyExclusions::default();
        type Run<'r> = &'r dyn Fn(&AnchoredSetVariable, &mut Vec<VariableValue>);
        let runs: [Run; 5] = [
            &|f, l| proxy.resolve(f, l),
            &|f, l| proxy.resolve_with_exclusions(f, l, &ke, None),
            &|f, l| proxy.resolve_key(f, b"a", l),
            &|f, l| proxy.resolve_regular_expression(f, &r, l),
            &|f, l| proxy.resolve_regular_expression_with_exclusions(f, &r, l, &ke, None),
        ];
        for run in runs {
            let (mut a, mut b) = (Vec::new(), Vec::new());
            run(&with, &mut a);
            run(&without, &mut b);
            assert!(!a.is_empty());
            assert_eq!(a, b);
            let pre = VariableValue::with_collection(b"TX", b"k", b"v");
            let (mut a, mut b) = (vec![pre.clone()], vec![pre]);
            run(&with, &mut a);
            run(&without, &mut b);
            assert_eq!(a, b);
            assert_eq!(a.last().unwrap().collection(), b"ARGS_NAMES");
        }
    }
}
