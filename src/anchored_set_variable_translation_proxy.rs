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
            let old = std::mem::take(v);
            let mut nv = VariableValue::with_collection(self.name.as_bytes(), old.key(), old.key());
            nv.reserve_origin(old.origin().len());
            for o in old.origin() {
                nv.add_origin(VariableOrigin::new(
                    old.key().len(),
                    o.offset.wrapping_sub(old.key().len()).wrapping_sub(1),
                ));
            }
            *v = nv;
        }
    }

    pub fn resolve(&self, fount: &AnchoredSetVariable, l: &mut Vec<VariableValue>) {
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
        fount.resolve_with_exclusions(l, ke, t);
        self.translate(l);
    }

    pub fn resolve_key(&self, fount: &AnchoredSetVariable, key: &[u8], l: &mut Vec<VariableValue>) {
        fount.resolve_key(key, l);
        self.translate(l);
    }

    pub fn resolve_regular_expression(&self, fount: &AnchoredSetVariable, r: &Regex, l: &mut Vec<VariableValue>) {
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
