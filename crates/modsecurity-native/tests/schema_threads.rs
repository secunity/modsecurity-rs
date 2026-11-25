//! Threads that load their first XML schemas at the same moment all load
//! them. libxml2 sets up its built-in schema types on the first schema it
//! parses, and that is not thread safe; `libxml2::init_parser` does it
//! first. The race is only in a process that has parsed no schema yet, so
//! each try is a process of its own, and there are enough of them that the
//! race would show: without the fix, 30 to 40% of such processes failed a
//! load (libxml2 2.14).
#![cfg(feature = "libxml2")]

use modsecurity_native::libxml2::Schema;

const SCHEMA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test/test-cases/data/SoapEnvelope.xsd");
const WORKER: &str = "MSRS_SCHEMA_THREADS_WORKER";
const THREADS: usize = 8;
const PROCESSES: usize = 20;

/// Run by [`first_schemas_of_concurrent_threads_load`] in a process of its
/// own: `THREADS` threads load the schema at once.
#[test]
#[ignore = "a worker process of first_schemas_of_concurrent_threads_load"]
fn worker() {
    if std::env::var_os(WORKER).is_none() {
        return;
    }
    let start = std::sync::Barrier::new(THREADS);
    let failed = std::thread::scope(|s| {
        let threads: Vec<_> = (0..THREADS)
            .map(|_| {
                s.spawn(|| {
                    start.wait();
                    Schema::load(SCHEMA, &mut |_| {}).is_err()
                })
            })
            .collect();
        threads.into_iter().map(|t| t.join().unwrap_or(true)).filter(|&failed| failed).count()
    });
    assert_eq!(failed, 0, "schema loads failed");
}

#[test]
fn first_schemas_of_concurrent_threads_load() {
    for _ in 0..PROCESSES {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "worker", "--ignored", "--quiet"])
            .env(WORKER, "1")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "a process failed to load its first schemas");
    }
}
