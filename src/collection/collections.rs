//! Port of `headers/modsecurity/collection/collections.h` and
//! `src/collection/collections.cc`.
//!
//! The per transaction view of the collections: the persistent collections
//! are borrowed from the `ModSecurity` instance, `TX` is owned.

use crate::collection::Collection;
use crate::collection::backend::in_memory_per_process::InMemoryPerProcess;

pub struct Collections<'a> {
    pub global_collection_key: Vec<u8>,
    pub ip_collection_key: Vec<u8>,
    pub session_collection_key: Vec<u8>,
    pub user_collection_key: Vec<u8>,
    pub resource_collection_key: Vec<u8>,
    pub global_collection: &'a dyn Collection,
    pub ip_collection: &'a dyn Collection,
    pub session_collection: &'a dyn Collection,
    pub user_collection: &'a dyn Collection,
    pub resource_collection: &'a dyn Collection,
    pub tx_collection: Box<InMemoryPerProcess>,
}

impl<'a> Collections<'a> {
    pub fn new(
        global: &'a dyn Collection,
        ip: &'a dyn Collection,
        session: &'a dyn Collection,
        user: &'a dyn Collection,
        resource: &'a dyn Collection,
    ) -> Self {
        Collections {
            global_collection_key: Vec::new(),
            ip_collection_key: Vec::new(),
            session_collection_key: Vec::new(),
            user_collection_key: Vec::new(),
            resource_collection_key: Vec::new(),
            global_collection: global,
            ip_collection: ip,
            session_collection: session,
            user_collection: user,
            resource_collection: resource,
            tx_collection: Box::new(InMemoryPerProcess::new("TX")),
        }
    }
}
