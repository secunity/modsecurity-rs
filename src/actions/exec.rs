//! Port of `src/actions/exec.cc`, `src/actions/exec.h`.
//!
//! `exec:/path/to/script.lua` — runs a Lua script when the rule matches.

use crate::actions::action::{Action, name_and_payload};
use crate::engine::lua::Lua;
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;
use crate::utils::system::find_resource;

#[derive(Debug)]
pub struct Exec {
    name: String,
    script: String,
    lua: Lua,
}

impl Exec {
    /// Finds and loads the script named by the payload.
    pub fn new(action: &str) -> Result<Self, String> {
        let (name, payload) = name_and_payload(action);
        let lookup = find_resource(payload, "");
        let Some(script) = lookup.path else {
            return Err(format!("exec: Script not found: {}", lookup.looked_at));
        };
        let lua = Lua::from_script(&script).map_err(|e| format!("exec: {}", e))?;
        Ok(Exec { name: name.to_string(), script, lua })
    }
}

impl Action for Exec {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, _rm: &mut RuleMessage<'_>) {
        crate::ms_dbg_a!(t, 8, "Running script... {}", self.script);
        self.lua.run(t, b"");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_not_found() {
        let err = Exec::new("exec:/nonexistent/msrs-script.lua").unwrap_err();
        assert!(err.starts_with("exec: Script not found: Looking at: '/nonexistent/msrs-script.lua'"), "{}", err);
    }
}
