//! Port of `src/actions/init_col.cc`, `src/actions/init_col.h`.
//!
//! `initcol:ip=%{REMOTE_ADDR}` — selects the record (key) of a persistent
//! collection for this transaction.

use crate::actions::action::{Action, name_and_payload};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;
use crate::utils::string::lossy;

#[derive(Debug)]
pub struct InitCol {
    name: String,
    collection_key: String,
    string: RunTimeString,
}

impl InitCol {
    /// `action` is `initcol:<collection>=`; `z` is the value.
    pub fn with_rts(action: &str, z: RunTimeString) -> Result<Self, String> {
        let (name, payload) = name_and_payload(action);
        if payload.len() < 2 {
            return Err("Something wrong with initcol format: too small".to_string());
        }
        let Some((collection_key, _)) = payload.split_once('=') else {
            return Err("Something wrong with initcol format: missing equals sign".to_string());
        };
        if !matches!(collection_key, "ip" | "global" | "resource") {
            return Err("Something wrong with initcol: collection must be `ip', `global' or `resource'".to_string());
        }
        Ok(InitCol { name: name.to_string(), collection_key: collection_key.to_string(), string: z })
    }
}

impl Action for InitCol {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, _rm: &mut RuleMessage<'_>) {
        let collection_name = self.string.evaluate(Some(t));
        let key = match self.collection_key.as_str() {
            "ip" => &mut t.collections.ip_collection_key,
            "global" => &mut t.collections.global_collection_key,
            "resource" => &mut t.collections.resource_collection_key,
            _ => return,
        };
        key.clone_from(&collection_name);
        crate::ms_dbg_a!(
            t,
            5,
            "Collection `{}' initialized with value: {}",
            self.collection_key,
            lossy(&collection_name)
        );
    }
}
