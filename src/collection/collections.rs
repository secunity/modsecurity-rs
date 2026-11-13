//! Collection ownership and the persistent records selected for a transaction.
//!
//! Persistent backends belong to the engine. Each transaction binds a backend
//! to its own selected record key, while owning its TX variables outright.

use crate::collection::transaction::TransactionVariables;
use crate::collection::{Collection, Persistent, compartment_key};
use crate::variable_value::VariableValue;
use crate::variables::variable::KeyExclusions;

/// A shared backend and the record selected by initcol/setsid/setuid/setrsc.
/// Keeping them together prevents callers from accidentally mixing collections
/// and keys. The web application compartment is supplied by the rule set.
pub struct CollectionBinding<'a> {
    backend: &'a dyn Collection,
    pub key: Vec<u8>,
}

impl<'a> CollectionBinding<'a> {
    fn new(backend: &'a dyn Collection) -> Self {
        Self { backend, key: Vec::new() }
    }

    pub fn get(&self, name: &[u8], app: &[u8]) -> Option<Vec<u8>> {
        self.backend.resolve_first(&compartment_key(name, &self.key, Some(app)))
    }

    pub fn set(&self, name: &[u8], app: &[u8], value: &[u8]) {
        self.backend.store_or_update_first(&compartment_key(name, &self.key, Some(app)), value);
    }

    pub fn remove(&self, name: &[u8], second_compartment: &[u8]) {
        self.backend.del(&compartment_key(name, &self.key, Some(second_compartment)));
    }

    pub fn set_expiry(&self, name: &[u8], app: &[u8], seconds: i32) {
        self.backend.set_expiry(&compartment_key(name, &self.key, Some(app)), seconds);
    }

    pub(crate) fn resolve(&self, name: &[u8], app: &[u8], out: &mut Vec<VariableValue>, exclusions: &KeyExclusions) {
        self.backend.resolve_multi_matches(&compartment_key(name, &self.key, Some(app)), out, exclusions);
    }

    pub(crate) fn resolve_regex(
        &self,
        pattern: &[u8],
        app: &[u8],
        out: &mut Vec<VariableValue>,
        exclusions: &KeyExclusions,
    ) {
        // Compile the compartment-prefixed expression on every evaluation,
        // preserving the backend's case-insensitive, multiline semantics.
        self.backend.resolve_regular_expression(&compartment_key(pattern, &self.key, Some(app)), out, exclusions);
    }
}

pub struct Collections<'a> {
    pub global: CollectionBinding<'a>,
    pub ip: CollectionBinding<'a>,
    pub session: CollectionBinding<'a>,
    pub user: CollectionBinding<'a>,
    pub resource: CollectionBinding<'a>,
    pub tx: TransactionVariables,
}

impl<'a> Collections<'a> {
    pub fn new(
        global: &'a dyn Collection,
        ip: &'a dyn Collection,
        session: &'a dyn Collection,
        user: &'a dyn Collection,
        resource: &'a dyn Collection,
    ) -> Self {
        Self {
            global: CollectionBinding::new(global),
            ip: CollectionBinding::new(ip),
            session: CollectionBinding::new(session),
            user: CollectionBinding::new(user),
            resource: CollectionBinding::new(resource),
            tx: TransactionVariables::default(),
        }
    }

    pub fn persistent(&self, collection: Persistent) -> &CollectionBinding<'a> {
        match collection {
            Persistent::Global => &self.global,
            Persistent::Ip => &self.ip,
            Persistent::Session => &self.session,
            Persistent::User => &self.user,
            Persistent::Resource => &self.resource,
        }
    }

    pub fn persistent_mut(&mut self, collection: Persistent) -> &mut CollectionBinding<'a> {
        match collection {
            Persistent::Global => &mut self.global,
            Persistent::Ip => &mut self.ip,
            Persistent::Session => &mut self.session,
            Persistent::User => &mut self.user,
            Persistent::Resource => &mut self.resource,
        }
    }
}
