//! Port of `src/actions/init_col.cc`, `src/actions/init_col.h`.
//!
//! `initcol:ip=%{REMOTE_ADDR}` — selects the record (key) of a persistent
//! collection for this transaction.

use crate::actions::action::{Action, ActionBase};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;
use crate::utils::string::lossy;

#[derive(Debug)]
pub struct InitCol {
    pub base: ActionBase,
    collection_key: String,
    pub string: RunTimeString,
}

impl InitCol {
    pub fn with_rts(action: &str, z: RunTimeString) -> Self {
        InitCol { base: ActionBase::new(action), collection_key: String::new(), string: z }
    }
}

impl Action for InitCol {
    crate::action_base_accessors!();

    fn init(&mut self) -> Result<(), String> {
        let payload = &self.base.parser_payload;
        if payload.len() < 2 {
            return Err("Something wrong with initcol format: too small".to_string());
        }
        let Some(pos_equals) = payload.find('=') else {
            return Err("Something wrong with initcol format: missing equals sign".to_string());
        };
        self.collection_key = payload[..pos_equals].to_string();
        if self.collection_key != "ip" && self.collection_key != "global" && self.collection_key != "resource" {
            return Err("Something wrong with initcol: collection must be `ip', `global' or `resource'".to_string());
        }
        Ok(())
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
