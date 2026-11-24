//! The redb collection backend.
//!
//! Persistent collections (`IP`, `SESSION`, `USER`, `GLOBAL`, `RESOURCE`)
//! stored in a redb file shared by every process using the library:
//! `./modsec-shared-collections.redb` (relative to the working
//! directory). The file is opened in redb's multi-writer mode: any number
//! of processes (nginx workers) read and write it, one write transaction
//! at a time. Values are stored as `CollectionData::serialize` (value +
//! expiry), as with LMDB, in one table of byte keys.
//!
//! The database is opened on first use and kept for the whole process.
#![cfg(feature = "redb")]

use std::sync::OnceLock;

use redb::{
    Builder, ConcurrencyMode, Database, ReadableDatabase, ReadableTable, TableDefinition, TableError, WriteTransaction,
};

use crate::backend::collection_data::CollectionData;
use crate::{Collection, StorageError};
use modsecurity_native::regex::Regex;
use modsecurity_types::KeyExclusions;
use modsecurity_types::variable_value::{VariableValue, move_to_front_reversed};

/// The location of the shared collections file.
const SHARED_COLLECTIONS_PATH: &str = "./modsec-shared-collections.redb";

/// The one table: key -> `CollectionData::serialize`.
const TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("collections");

static SHARED: OnceLock<Result<Database, String>> = OnceLock::new();

/// The database of the process, opened at `path` on first use (later calls
/// get that one, whatever their path).
fn shared(path: &str) -> Result<&'static Database, StorageError> {
    let opened = SHARED.get_or_init(|| {
        Builder::new().set_concurrency_mode(ConcurrencyMode::MultiWriter).create(path).map_err(|e| e.to_string())
    });
    opened.as_ref().map_err(|e| StorageError::new("open", e.clone()))
}

/// A collection stored in the shared redb database.
pub struct Redb {
    name: String,
}

impl Redb {
    pub fn new(name: &str) -> Self {
        Redb { name: name.to_string() }
    }

    fn database(&self) -> Result<&'static Database, StorageError> {
        shared(SHARED_COLLECTIONS_PATH)
    }

    /// Runs `f` in a write transaction and commits it. A failure leaves
    /// the database as it was.
    fn write(&self, f: impl FnOnce(&WriteTransaction) -> Result<(), StorageError>) -> Result<(), StorageError> {
        let txn = self.database()?.begin_write().map_err(failed("begin"))?;
        f(&txn)?;
        txn.commit().map_err(failed("commit"))
    }

    /// Writes `key` with the value computed from its previous data (if any)
    /// in one write transaction: the shared body of `store_or_update_first`
    /// and `set_expiry`.
    fn replace(&self, key: &[u8], build: impl FnOnce(CollectionData) -> CollectionData) -> Result<(), StorageError> {
        self.write(|txn| {
            let mut table = txn.open_table(TABLE).map_err(failed("open table"))?;
            let previous = table.get(key).map_err(failed("get"))?.map(|v| CollectionData::from_bytes(v.value()));
            let data = build(previous.unwrap_or_default()).serialize();
            table.insert(key, data.as_slice()).map_err(failed("put"))?;
            Ok(())
        })
    }

    /// Deletes `key` (only when it has expired with `expired_only`), in its
    /// own write transaction. A key that is not there is not an error.
    fn delete(&self, key: &[u8], expired_only: bool) -> Result<(), StorageError> {
        self.write(|txn| {
            let mut table = txn.open_table(TABLE).map_err(failed("open table"))?;
            let expired = match table.get(key).map_err(failed("get"))? {
                None => return Ok(()),
                Some(v) => CollectionData::from_bytes(v.value()).is_expired(),
            };
            if !expired_only || expired {
                table.remove(key).map_err(failed("del"))?;
            }
            Ok(())
        })
    }

    /// Calls `f(key, value)` for the entries whose key `selected` accepts,
    /// among those that start with `prefix` (keys are sorted: the walk
    /// begins at the first of them and ends after the last). Entries that
    /// have expired are left out and deleted afterwards (best effort); so
    /// are entries without a value.
    fn walk(
        &self,
        prefix: &[u8],
        selected: impl Fn(&[u8]) -> bool,
        mut f: impl FnMut(&[u8], &[u8]),
    ) -> Result<(), StorageError> {
        let mut expired = Vec::new();
        {
            let txn = self.database()?.begin_read().map_err(failed("begin"))?;
            let table = match txn.open_table(TABLE) {
                Ok(table) => table,
                // Nothing was ever stored.
                Err(TableError::TableDoesNotExist(_)) => return Ok(()),
                Err(e) => return Err(failed("open table")(e)),
            };
            for entry in table.range(prefix..).map_err(failed("cursor"))? {
                // An entry that cannot be read ends the walk, as with LMDB.
                let Ok((key, data)) = entry else { break };
                let key = key.value();
                if !key.starts_with(prefix) {
                    break;
                }
                if !selected(key) {
                    continue;
                }
                let record = CollectionData::from_bytes(data.value());
                if record.is_expired() {
                    expired.push(key.to_vec());
                } else if let Some(value) = &record.value {
                    f(key, value);
                }
            }
        }
        for key in &expired {
            let _ = self.delete(key, true);
        }
        Ok(())
    }
}

/// A failure of redb in `operation`.
fn failed<E: std::fmt::Display>(operation: &'static str) -> impl Fn(E) -> StorageError {
    move |e| StorageError::new(operation, e.to_string())
}

impl Collection for Redb {
    fn store_or_update_first(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        self.replace(key, |mut record| {
            record.set_value(value);
            record
        })
    }

    fn del(&self, key: &[u8]) -> Result<(), StorageError> {
        self.delete(key, false)
    }

    fn set_expiry(&self, key: &[u8], expiry_seconds: u64) -> Result<(), StorageError> {
        self.replace(key, |mut record| {
            record.set_expiry(expiry_seconds);
            record
        })
    }

    fn resolve_first(&self, var: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        let record = {
            let txn = self.database()?.begin_read().map_err(failed("begin"))?;
            let table = match txn.open_table(TABLE) {
                Ok(table) => table,
                Err(TableError::TableDoesNotExist(_)) => return Ok(None),
                Err(e) => return Err(failed("open table")(e)),
            };
            table.get(var).map_err(failed("get"))?.map(|v| CollectionData::from_bytes(v.value()))
        };
        match record {
            Some(record) if record.is_expired() => {
                let _ = self.delete(var, true);
                Ok(None)
            }
            Some(record) => Ok(record.value),
            None => Ok(None),
        }
    }

    fn resolve_multi_matches(
        &self,
        var: &[u8],
        l: &mut Vec<VariableValue>,
        ke: &KeyExclusions,
    ) -> Result<(), StorageError> {
        let name = self.name.as_bytes();
        let start = l.len();
        // Every key, or the key `var` alone.
        self.walk(
            var,
            |k| (var.is_empty() || k == var) && !ke.to_omit(k),
            |k, d| l.push(VariableValue::with_collection(name, k, d)),
        )?;
        move_to_front_reversed(l, start);
        Ok(())
    }

    fn resolve_regex(
        &self,
        prefix: &[u8],
        r: &Regex,
        l: &mut Vec<VariableValue>,
        ke: &KeyExclusions,
    ) -> Result<(), StorageError> {
        let name = self.name.as_bytes();
        let start = l.len();
        let selected = |k: &[u8]| r.is_match(&k[prefix.len()..]) && !ke.to_omit(k);
        self.walk(prefix, selected, |k, d| l.push(VariableValue::with_collection(name, k, d)))?;
        move_to_front_reversed(l, start);
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// The database file of the tests of this process.
    fn temp_path() -> String {
        let dir = std::env::temp_dir().join(format!("msrs-redb-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("modsec-shared-collections.redb").to_str().unwrap().to_string()
    }

    /// Opens the database of the tests of this process (if none is open).
    pub(in crate::backend) fn database_in_temp_dir() {
        shared(&temp_path()).unwrap();
    }

    const WORKER: &str = "MSRS_REDB_WORKER";
    const KEYS_PER_WORKER: usize = 200;

    /// Run by [`processes_share_the_collections`] in a process of its own:
    /// writes its keys to the file named in `MSRS_REDB_WORKER`.
    #[test]
    #[ignore = "a worker process of processes_share_the_collections"]
    fn worker() {
        let Ok(spec) = std::env::var(WORKER) else { return };
        let (path, prefix) = spec.split_once('|').unwrap();
        shared(path).unwrap();
        let c = Redb::new("IP");
        for i in 0..KEYS_PER_WORKER {
            c.store_or_update_first(format!("{prefix}{i}").as_bytes(), b"v").unwrap();
        }
    }

    /// Processes write to one file at the same time, while this one has it
    /// open, and each sees what the others wrote.
    #[test]
    fn processes_share_the_collections() {
        database_in_temp_dir();
        let path = temp_path();
        let run = format!("p{}-", std::process::id());
        let workers: Vec<_> = (0..4)
            .map(|w| {
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", "backend::redb::tests::worker", "--ignored", "--quiet"])
                    .env(WORKER, format!("{path}|{run}{w}-"))
                    .stdout(std::process::Stdio::null())
                    .spawn()
                    .unwrap()
            })
            .collect();
        for mut w in workers {
            assert!(w.wait().unwrap().success());
        }
        let mut l = Vec::new();
        Redb::new("IP").resolve_multi_matches(b"", &mut l, &KeyExclusions::default()).unwrap();
        let mine = l.iter().filter(|v| v.key().starts_with(run.as_bytes())).count();
        assert_eq!(mine, 4 * KEYS_PER_WORKER);
    }

    /// The errors of redb are reported with what redb said.
    #[test]
    fn errors_carry_the_message() {
        let error = failed("get")("table is broken");
        assert_eq!(error.to_string(), "get failed (table is broken)");
    }
}
