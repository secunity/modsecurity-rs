//! Port of `headers/modsecurity/variable_value.h`.
//!
//! Keys and values are byte strings: they come straight from the HTTP
//! request.

use std::sync::Arc;

use crate::variable_origin::VariableOrigin;

/// Inserts `items` at the front of `l` one after the other, in order, as the
/// C++ code does with `l->insert(l->begin(), ...)` in a loop: the result is
/// `items` reversed, followed by the previous contents of `l`.
///
/// The C++ vector holds pointers, so its repeated front insertion is cheap
/// per element; with owned values it must be done in one splice to stay
/// linear (resolving `ARGS` with hundreds of arguments for every rule
/// otherwise dominates the evaluation time).
pub fn prepend_each(l: &mut Vec<VariableValue>, items: Vec<VariableValue>) {
    if items.is_empty() {
        return;
    }
    l.splice(0..0, items.into_iter().rev());
}

pub type Origins = Vec<VariableOrigin>;

/// A resolved variable: collection name, key and value, plus where the value
/// came from. In C++ resolution produced heap allocated copies owned by the
/// caller; here resolution produces owned values in a `Vec`.
///
/// Resolving a collection (e.g. `ARGS`, once per rule that targets it)
/// copies its values, so the data is shared behind an `Arc` and a copy only
/// bumps a reference count; the rare modifications (`set_value`,
/// `add_origin`) copy on write. The collection name and the key are stored
/// once, inside `key_with_collection`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VariableValue(Arc<Inner>);

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Inner {
    origin: Origins,
    /// `collection:key`, or just `key` when there is no collection.
    key_with_collection: Vec<u8>,
    /// Length of the collection name in `key_with_collection` (`None`: no
    /// collection).
    collection_len: Option<usize>,
    value: Vec<u8>,
}

impl VariableValue {
    /// `VariableValue(const std::string *key, const std::string *value)`
    pub fn new(key: &[u8], value: &[u8]) -> Self {
        VariableValue(Arc::new(Inner {
            origin: Vec::new(),
            key_with_collection: key.to_vec(),
            collection_len: None,
            value: value.to_vec(),
        }))
    }

    /// `VariableValue(collection, key, value)`
    pub fn with_collection(collection: &[u8], key: &[u8], value: &[u8]) -> Self {
        let mut kwc = Vec::with_capacity(collection.len() + 1 + key.len());
        kwc.extend_from_slice(collection);
        kwc.push(b':');
        kwc.extend_from_slice(key);
        VariableValue(Arc::new(Inner {
            origin: Vec::new(),
            key_with_collection: kwc,
            collection_len: Some(collection.len()),
            value: value.to_vec(),
        }))
    }

    pub fn key(&self) -> &[u8] {
        match self.0.collection_len {
            Some(n) => &self.0.key_with_collection[n + 1..],
            None => &self.0.key_with_collection,
        }
    }

    pub fn key_with_collection(&self) -> &[u8] {
        &self.0.key_with_collection
    }

    pub fn collection(&self) -> &[u8] {
        match self.0.collection_len {
            Some(n) => &self.0.key_with_collection[..n],
            None => b"",
        }
    }

    pub fn value(&self) -> &[u8] {
        &self.0.value
    }

    pub fn set_value(&mut self, value: &[u8]) {
        let inner = Arc::make_mut(&mut self.0);
        inner.value.clear();
        inner.value.extend_from_slice(value);
    }

    pub fn add_origin(&mut self, origin: VariableOrigin) {
        Arc::make_mut(&mut self.0).origin.push(origin);
    }

    pub fn origin(&self) -> &Origins {
        &self.0.origin
    }

    pub fn reserve_origin(&mut self, additional: usize) {
        Arc::make_mut(&mut self.0).origin.reserve(additional);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepend_each_matches_repeated_front_insertion() {
        let v = |s: &str| VariableValue::new(s.as_bytes(), b"");
        let existing = vec![v("x"), v("y")];
        let items = vec![v("a"), v("b"), v("c")];

        let mut expected = existing.clone();
        for it in items.clone() {
            expected.insert(0, it);
        }
        let mut got = existing;
        prepend_each(&mut got, items);
        assert_eq!(got, expected);
        let keys: Vec<&[u8]> = got.iter().map(|x| x.key()).collect();
        assert_eq!(keys, [b"c".as_slice(), b"b", b"a", b"x", b"y"]);
    }

    #[test]
    fn accessors_and_copy_on_write() {
        let v = VariableValue::with_collection(b"ARGS", b"a:b", b"1");
        assert_eq!((v.collection(), v.key(), v.key_with_collection()), (&b"ARGS"[..], &b"a:b"[..], &b"ARGS:a:b"[..]));
        let e = VariableValue::with_collection(b"", b"", b"");
        assert_eq!((e.collection(), e.key(), e.key_with_collection()), (&b""[..], &b""[..], &b":"[..]));
        let n = VariableValue::new(b"k", b"v");
        assert_eq!((n.collection(), n.key(), n.key_with_collection()), (&b""[..], &b"k"[..], &b"k"[..]));

        let mut c = v.clone();
        c.set_value(b"2");
        c.add_origin(VariableOrigin::new(1, 0));
        assert_eq!((v.value(), v.origin().len()), (&b"1"[..], 0));
        assert_eq!((c.value(), c.origin().len()), (&b"2"[..], 1));
    }
}
