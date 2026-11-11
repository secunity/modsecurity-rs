//! Port of `src/variables/env.cc`, `src/variables/env.h`.
//!
//! `ENV` / `ENV:name`: the process environment plus the variables set with
//! the `setenv` action (`Transaction::variable_envs`).

use std::collections::BTreeMap;
use std::os::unix::ffi::OsStrExt;

use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;
use crate::variable_value::VariableValue;
use crate::variables::variable::{Variable, VariableBase};

/// `Env`
#[derive(Debug)]
pub struct Env {
    pub base: VariableBase,
}

impl Env {
    /// `Env(name)`: `ENV` or `ENV:<key>`.
    pub fn new(name: &str) -> Self {
        Env { base: VariableBase::new(name) }
    }
}

impl Variable for Env {
    fn base(&self) -> &VariableBase {
        &self.base
    }
    fn base_mut(&mut self) -> &mut VariableBase {
        &mut self.base
    }
    fn evaluate(&self, t: &Transaction<'_>, _rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        // The C++ code inserts the process environment into
        // `m_variableEnvs` (`std::map::insert`, so the values set by
        // `setenv` win) and then walks the map. The transaction is shared
        // here, so the merge is done on a copy; the result is the same.
        // (`std::env::vars_os` splits each entry at the first `=` after the
        // first character, where C++ splits at the first `=`: only an entry
        // starting with `=` would differ.)
        let mut envs: BTreeMap<Vec<u8>, Vec<u8>> = t.variable_envs.clone();
        for (k, v) in std::env::vars_os() {
            envs.entry(k.as_bytes().to_vec()).or_insert_with(|| v.as_bytes().to_vec());
        }

        let name = self.base.name.as_bytes();
        let has_name = !name.is_empty();
        for (k, v) in &envs {
            if has_name && k.as_slice() != name {
                continue;
            }
            let key: &[u8] = if has_name { name } else { k };
            if !self.base.key_exclusion.to_omit(key) {
                l.push(VariableValue::with_collection(self.base.collection_name.as_bytes(), key, v));
            }
        }
    }
}
