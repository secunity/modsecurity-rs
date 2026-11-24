//! The storage backends of the persistent collections.

pub mod collection_data;
// The backend of the persistent collections in builds without LMDB.
pub mod in_memory_per_process;
pub mod lmdb;
pub mod redb;

/// What every backend does, checked for each of them with the same code.
#[cfg(test)]
mod contract {
    use crate::Collection;
    use modsecurity_native::regex::Regex;
    use modsecurity_types::variable_value::VariableValue;
    use modsecurity_types::{KeyExclusion, KeyExclusions};

    /// The (key with collection, value) pairs of a result, sorted: the
    /// order of the entries is the backend's own.
    fn pairs(mut l: Vec<VariableValue>) -> Vec<(String, String)> {
        l.sort_by(|a, b| a.key().cmp(b.key()));
        let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
        l.iter().map(|v| (text(v.key_with_collection()), text(v.value()))).collect()
    }

    /// `c` is a collection named `IP`; `p` makes the keys of this run
    /// unique (a backend may be shared with other tests and runs).
    fn check(c: &dyn Collection, p: &str) {
        let k = |compartment: &str, name: &str| format!("{p}{compartment}::app::{name}").into_bytes();
        let shown = |compartment: &str, name: &str| format!("IP:{p}{compartment}::app::{name}");
        let none = KeyExclusions::default();
        for (compartment, name, value) in
            [("one", "a", "1"), ("one", "ab", "2"), ("one", "b", "3"), ("two", "a", "4"), ("one", "gone", "5")]
        {
            c.store_or_update_first(&k(compartment, name), value.as_bytes()).unwrap();
        }
        c.set_expiry(&k("one", "gone"), 0).unwrap();
        c.set_expiry(&k("one", "b"), 1000).unwrap();
        c.set_expiry(&k("one", "expiry-only"), 1000).unwrap();

        // One key.
        assert_eq!(c.resolve_first(&k("one", "a")).unwrap(), Some(b"1".to_vec()));
        assert_eq!(c.resolve_first(&k("one", "missing")).unwrap(), None);
        assert_eq!(c.resolve_first(&k("one", "gone")).unwrap(), None, "expired");
        assert_eq!(c.resolve_first(&k("one", "expiry-only")).unwrap(), None);
        assert_eq!(c.resolve_first(&k("one", "b")).unwrap(), Some(b"3".to_vec()), "not expired yet");

        // The entries of one key: that key alone, not the keys it begins.
        let mut l = Vec::new();
        c.resolve_multi_matches(&k("one", "a"), &mut l, &none).unwrap();
        assert_eq!(pairs(l), [(shown("one", "a"), "1".to_string())]);
        let mut l = Vec::new();
        let excluded = KeyExclusions(vec![KeyExclusion::string(&String::from_utf8(k("one", "a")).unwrap())]);
        c.resolve_multi_matches(&k("one", "a"), &mut l, &excluded).unwrap();
        assert!(l.is_empty(), "an excluded key");

        // Every entry: the live ones of this run are among them.
        let mut l = Vec::new();
        c.resolve_multi_matches(b"", &mut l, &excluded).unwrap();
        let all = pairs(l);
        let mine: Vec<_> = all.iter().filter(|(key, _)| key.starts_with(&format!("IP:{p}"))).cloned().collect();
        assert_eq!(
            mine,
            [
                (shown("one", "ab"), "2".to_string()),
                (shown("one", "b"), "3".to_string()),
                (shown("two", "a"), "4".to_string())
            ]
        );

        // The names of one compartment that match an expression.
        let prefix = format!("{p}one::app::");
        let mut l = Vec::new();
        c.resolve_regex(prefix.as_bytes(), &Regex::new_case("^a", true), &mut l, &none).unwrap();
        assert_eq!(pairs(l), [(shown("one", "a"), "1".to_string()), (shown("one", "ab"), "2".to_string())]);
        let mut l = Vec::new();
        c.resolve_regex(prefix.as_bytes(), &Regex::new_case(".", true), &mut l, &excluded).unwrap();
        assert_eq!(pairs(l), [(shown("one", "ab"), "2".to_string()), (shown("one", "b"), "3".to_string())]);

        // Removal.
        c.del(&k("one", "a")).unwrap();
        c.del(&k("one", "missing")).unwrap();
        assert_eq!(c.resolve_first(&k("one", "a")).unwrap(), None);
        assert_eq!(c.resolve_first(&k("one", "ab")).unwrap(), Some(b"2".to_vec()));
        for (compartment, name) in [("one", "ab"), ("one", "b"), ("two", "a"), ("one", "expiry-only")] {
            c.del(&k(compartment, name)).unwrap();
        }
    }

    fn run_id() -> String {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos());
        format!("contract-{}-{now}-", std::process::id())
    }

    #[test]
    fn in_memory() {
        check(&super::in_memory_per_process::InMemoryPerProcess::new("IP"), &run_id());
    }

    #[cfg(feature = "redb")]
    #[test]
    fn redb() {
        super::redb::tests::database_in_temp_dir();
        check(&super::redb::Redb::new("IP"), &run_id());
    }

    #[cfg(feature = "lmdb")]
    #[test]
    fn lmdb() {
        super::lmdb::tests::provider_in_temp_dir();
        check(&super::lmdb::Lmdb::new("IP"), &run_id());
    }
}
