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

        // Updates from the current value.
        let add = |n: u64| {
            move |v: Option<&[u8]>| -> Vec<u8> {
                let current = v.map_or(0, |v| std::str::from_utf8(v).unwrap().parse::<u64>().unwrap());
                (current + n).to_string().into_bytes()
            }
        };
        assert_eq!(c.update_first(&k("one", "n"), &mut add(2)).unwrap(), b"2", "a new key");
        assert_eq!(c.update_first(&k("one", "n"), &mut add(3)).unwrap(), b"5");
        assert_eq!(c.resolve_first(&k("one", "n")).unwrap(), Some(b"5".to_vec()));
        c.set_expiry(&k("one", "n"), 1000).unwrap();
        c.update_first(&k("one", "n"), &mut add(1)).unwrap();
        c.set_expiry(&k("one", "n"), 0).unwrap();
        assert_eq!(c.update_first(&k("one", "n"), &mut add(1)).unwrap(), b"1", "an expired value starts over");
        assert_eq!(c.resolve_first(&k("one", "n")).unwrap(), Some(b"1".to_vec()), "without its expiry");
        c.set_expiry(&k("one", "m"), 1000).unwrap();
        assert_eq!(c.update_first(&k("one", "m"), &mut add(4)).unwrap(), b"4", "an expiry alone");
        c.del(&k("one", "n")).unwrap();
        c.del(&k("one", "m")).unwrap();

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

    // The multi-process tests, for the backends whose file processes share.
    #[cfg(any(feature = "lmdb", feature = "redb"))]
    const WORKER: &str = "MSRS_COLLECTION_WORKER";
    #[cfg(any(feature = "lmdb", feature = "redb"))]
    const WRITES_PER_WORKER: usize = 100;

    /// The backend `name` with its file at `path`.
    #[cfg(any(feature = "lmdb", feature = "redb"))]
    fn backend_at(name: &str, path: &str) -> Box<dyn Collection> {
        match name {
            #[cfg(feature = "lmdb")]
            "lmdb" => {
                super::lmdb::tests::open_at(path);
                Box::new(super::lmdb::Lmdb::new("IP"))
            }
            #[cfg(feature = "redb")]
            "redb" => {
                super::redb::tests::open_at(path);
                Box::new(super::redb::Redb::new("IP"))
            }
            _ => panic!("no backend {name} in this build"),
        }
    }

    /// Run by [`processes_share`] in a process of its own: a writer writes
    /// its keys and adds 1 to the shared counter as many times; the
    /// checker (`check`) then finds every key and the whole count.
    #[cfg(any(feature = "lmdb", feature = "redb"))]
    #[test]
    #[ignore = "a worker process of the multi-process tests"]
    fn worker() {
        let Ok(spec) = std::env::var(WORKER) else { return };
        let [name, path, run, me] = spec.split('|').collect::<Vec<_>>()[..] else { panic!("{spec}") };
        let c = backend_at(name, path);
        let counter = format!("{run}counter").into_bytes();
        if me == "check" {
            let mut l = Vec::new();
            c.resolve_multi_matches(b"", &mut l, &KeyExclusions::default()).unwrap();
            let written = l.iter().filter(|v| v.key().starts_with(format!("{run}w").as_bytes())).count();
            assert_eq!(written, 4 * WRITES_PER_WORKER);
            let total = (4 * WRITES_PER_WORKER).to_string().into_bytes();
            assert_eq!(c.resolve_first(&counter).unwrap(), Some(total));
            return;
        }
        let mut add_one = |v: Option<&[u8]>| -> Vec<u8> {
            let current = v.map_or(0, |v| std::str::from_utf8(v).unwrap().parse::<u64>().unwrap());
            (current + 1).to_string().into_bytes()
        };
        for i in 0..WRITES_PER_WORKER {
            c.store_or_update_first(format!("{run}{me}-{i}").as_bytes(), b"v").unwrap();
            c.update_first(&counter, &mut add_one).unwrap();
        }
    }

    /// Four processes write to one file at the same time; a fifth then
    /// finds what each wrote, and no increment of the shared counter is
    /// lost. (Processes of their own: the one of the tests may have opened
    /// another file already.)
    #[cfg(any(feature = "lmdb", feature = "redb"))]
    fn processes_share(name: &str) {
        let dir = std::env::temp_dir().join(format!("msrs-{name}-processes-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("collections").to_str().unwrap().to_string();
        let run = run_id();
        let spawn = |me: &str| {
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "backend::contract::worker", "--ignored", "--quiet"])
                .env(WORKER, format!("{name}|{path}|{run}|{me}"))
                .stdout(std::process::Stdio::null())
                .spawn()
                .unwrap()
        };
        let writers: Vec<_> = (0..4).map(|w| spawn(&format!("w{w}"))).collect();
        for mut w in writers {
            assert!(w.wait().unwrap().success(), "a writer failed");
        }
        assert!(spawn("check").wait().unwrap().success(), "the checker failed");
    }

    #[cfg(feature = "lmdb")]
    #[test]
    fn lmdb_processes_share() {
        processes_share("lmdb");
    }

    #[cfg(feature = "redb")]
    #[test]
    fn redb_processes_share() {
        processes_share("redb");
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
