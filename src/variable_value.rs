//! Port of `headers/modsecurity/variable_value.h`.
//!
//! Keys and values are byte strings: they come straight from the HTTP
//! request.

use std::sync::Arc;

use crate::variable_origin::VariableOrigin;

/// Moves the values pushed onto `l` from index `start` on to its front, in
/// reverse order: the result of the C++ code's `l->insert(l->begin(), ...)`
/// for each of them in turn, i.e. the new values reversed, followed by the
/// previous contents of `l`.
///
/// The C++ vector holds pointers, so its repeated front insertion is cheap
/// per element; with owned values it must be done in one pass to stay
/// linear (resolving `ARGS` with hundreds of arguments for every rule
/// otherwise dominates the evaluation time). Callers push straight onto `l`
/// and call this once, which needs no temporary list.
pub fn move_to_front_reversed(l: &mut [VariableValue], start: usize) {
    let added = l.len() - start;
    l[start..].reverse();
    l.rotate_right(added);
}

pub type Origins = Vec<VariableOrigin>;

/// A resolved variable: collection name, key and value, plus where the value
/// came from. In C++ resolution produced heap allocated copies owned by the
/// caller; here resolution produces owned values in a `Vec`.
///
/// Resolving a collection (e.g. `ARGS`, once per rule that targets it)
/// copies its values, so the data is shared behind an `Arc` and a copy only
/// bumps a reference count; the rare modifications (`set_value`,
/// `add_origin`) copy on write. The collection name, key and value share
/// one buffer: `collection:key` (or just `key`) followed by the value.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VariableValue(Arc<Inner>);

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Inner {
    origin: Origins,
    /// `collection:key` (or just `key` when there is no collection), then
    /// the value.
    data: Vec<u8>,
    /// Length of the `collection:key` / `key` part of `data`.
    kwc_len: usize,
    /// Length of the collection name (`None`: no collection).
    collection_len: Option<usize>,
}

impl VariableValue {
    /// `VariableValue(const std::string *key, const std::string *value)`
    pub fn new(key: &[u8], value: &[u8]) -> Self {
        let mut data = Vec::with_capacity(key.len() + value.len());
        data.extend_from_slice(key);
        data.extend_from_slice(value);
        VariableValue(Arc::new(Inner { origin: Vec::new(), data, kwc_len: key.len(), collection_len: None }))
    }

    /// `VariableValue(collection, key, value)`
    pub fn with_collection(collection: &[u8], key: &[u8], value: &[u8]) -> Self {
        let kwc_len = collection.len() + 1 + key.len();
        let mut data = Vec::with_capacity(kwc_len + value.len());
        data.extend_from_slice(collection);
        data.push(b':');
        data.extend_from_slice(key);
        data.extend_from_slice(value);
        VariableValue(Arc::new(Inner { origin: Vec::new(), data, kwc_len, collection_len: Some(collection.len()) }))
    }

    pub fn key(&self) -> &[u8] {
        let kwc = self.key_with_collection();
        match self.0.collection_len {
            Some(n) => &kwc[n + 1..],
            None => kwc,
        }
    }

    pub fn key_with_collection(&self) -> &[u8] {
        &self.0.data[..self.0.kwc_len]
    }

    pub fn collection(&self) -> &[u8] {
        match self.0.collection_len {
            Some(n) => &self.0.data[..n],
            None => b"",
        }
    }

    pub fn value(&self) -> &[u8] {
        &self.0.data[self.0.kwc_len..]
    }

    pub fn set_value(&mut self, value: &[u8]) {
        let inner = Arc::make_mut(&mut self.0);
        inner.data.truncate(inner.kwc_len);
        inner.data.extend_from_slice(value);
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
    fn move_to_front_reversed_matches_repeated_front_insertion() {
        let v = |s: &str| VariableValue::new(s.as_bytes(), b"");
        for existing in [vec![], vec![v("x"), v("y")]] {
            let items = vec![v("a"), v("b"), v("c")];
            let mut expected = existing.clone();
            for it in items.clone() {
                expected.insert(0, it);
            }
            let mut got = existing.clone();
            let start = got.len();
            got.extend(items);
            move_to_front_reversed(&mut got, start);
            assert_eq!(got, expected);
        }
        let mut none = vec![v("x")];
        move_to_front_reversed(&mut none, 1);
        assert_eq!(none, vec![v("x")]);
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
