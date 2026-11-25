//! The `ENV` variable (`ENV` / `ENV:name`): the process environment plus
//! the variables set with the `setenv` action
//! (`Transaction::variable_envs`).

use std::collections::BTreeMap;
use std::os::unix::ffi::OsStrExt;

use crate::transaction::Transaction;
use crate::variables::variable::Variable;
use crate::variables::variable_value::VariableValue;

/// `ENV` (every variable) or `ENV:<name>`: the process environment plus
/// what `setenv` set in the transaction.
pub(crate) fn evaluate(var: &Variable, t: &Transaction<'_>, l: &mut Vec<VariableValue>) {
    // The process environment is merged into the variables set by
    // `setenv`, which win over an entry of the same name, and the result is
    // walked in key order. The transaction is shared here, so the merge is
    // done on a copy.
    // (`std::env::vars_os` splits each entry at the first `=` after the
    // first character, so the name of an entry starting with `=` keeps
    // that `=`.)
    let mut envs: BTreeMap<Vec<u8>, Vec<u8>> = t.variable_envs.clone();
    for (k, v) in std::env::vars_os() {
        envs.entry(k.as_bytes().to_vec()).or_insert_with(|| v.as_bytes().to_vec());
    }

    let name = var.name().as_bytes();
    let has_name = !name.is_empty();
    for (k, v) in &envs {
        if has_name && k.as_slice() != name {
            continue;
        }
        let key: &[u8] = if has_name { name } else { k };
        if !var.key_exclusion().to_omit(key) {
            l.push(VariableValue::with_collection(var.collection_name().as_bytes(), key, v));
        }
    }
}
