//! `initcol:ip=%{REMOTE_ADDR}` — selects the record (key) of a persistent
//! collection for this transaction.

use crate::actions::action::Action;
use crate::actions::context::ActionContext;
use crate::collection::Persistent;
use crate::run_time_string::RunTimeString;

#[derive(Debug)]
pub struct InitCol {
    name: String,
    collection: Persistent,
    string: RunTimeString,
}

impl InitCol {
    /// `payload` is `<collection>=<value>`; `z` is the value, the key to
    /// select.
    pub fn with_rts(name: &str, payload: &str, z: RunTimeString) -> Result<Self, String> {
        if payload.len() < 2 {
            return Err("Something wrong with initcol format: too small".to_string());
        }
        let Some((collection_key, _)) = payload.split_once('=') else {
            return Err("Something wrong with initcol format: missing equals sign".to_string());
        };
        // SESSION and USER are initialised by `setsid` and `setuid`.
        let collection = match Persistent::parse(collection_key.as_bytes()) {
            Some(c @ (Persistent::Ip | Persistent::Global | Persistent::Resource)) => c,
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
        crate::ms_dbg!(
            cx,
            5,
            "Collection `{}' initialized with value: {}",
            self.collection.name().to_ascii_lowercase(),
            String::from_utf8_lossy(cx.collection_key(self.collection))
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The collection is named in any case, as in `setvar` and the rule
    /// targets. (`initcol` used to know only lowercase names.)
    #[test]
    fn collection_names_ignore_case() {
        let z = || RunTimeString::from_text("x");
        for (payload, collection) in [("ip=", Persistent::Ip), ("IP=", Persistent::Ip), ("Global=", Persistent::Global)]
        {
            assert_eq!(InitCol::with_rts("initcol", payload, z()).unwrap().collection, collection, "{payload}");
        }
        for payload in ["session=", "USER=", "tx="] {
            assert!(
                InitCol::with_rts("initcol", payload, z()).unwrap_err().contains("collection must be"),
                "{payload}"
            );
        }
    }
}
