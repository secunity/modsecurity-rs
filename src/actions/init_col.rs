//! `initcol:ip=%{REMOTE_ADDR}` — selects the record (key) of a persistent
//! collection for this transaction.

use crate::actions::action::{Action, name_and_payload};
use crate::actions::context::ActionContext;
use crate::collection::Persistent;
use crate::run_time_string::RunTimeString;
use crate::utils::string::lossy;

#[derive(Debug)]
pub struct InitCol {
    name: String,
    collection: Persistent,
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
        let collection = match collection_key {
            "ip" => Persistent::Ip,
            "global" => Persistent::Global,
            "resource" => Persistent::Resource,
            _ => {
                return Err("Something wrong with initcol: collection must be `ip', `global' or `resource'".to_string());
            }
        };
        Ok(InitCol { name: name.to_string(), collection, string: z })
    }
}

impl Action for InitCol {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, cx: &mut ActionContext<'_, '_, '_>) {
        let collection_name = cx.expand(&self.string);
        cx.init_collection(self.collection, collection_name);
        crate::act_dbg!(
            cx,
            5,
            "Collection `{}' initialized with value: {}",
            self.collection.name().to_ascii_lowercase(),
            lossy(cx.collection_key(self.collection))
        );
    }
}
