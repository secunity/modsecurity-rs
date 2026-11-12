//! Port of `src/actions/exec.cc`, `src/actions/exec.h`.
//!
//! `exec:/path/to/script.lua` — runs a Lua script when the rule matches.

use crate::actions::action::{Action, ActionBase};
use crate::engine::lua::Lua;
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;
use crate::utils::system::find_resource;

#[derive(Debug)]
pub struct Exec {
    pub base: ActionBase,
    script: String,
    lua: Lua,
}

impl Exec {
    pub fn new(action: &str) -> Self {
        Exec { base: ActionBase::new(action), script: String::new(), lua: Lua::new() }
    }
}

impl Action for Exec {
    crate::action_base_accessors!();

    fn init(&mut self) -> Result<(), String> {
        let lookup = find_resource(&self.base.parser_payload, "");
        let Some(script) = lookup.path else {
            return Err(format!("exec: Script not found: {}", lookup.looked_at));
        };
        self.lua = Lua::from_script(&script).map_err(|e| format!("exec: {}", e))?;
        self.script = script;
        Ok(())
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
        let mut e = Exec::new("exec:/nonexistent/msrs-script.lua");
        let err = e.init().unwrap_err();
        assert!(err.starts_with("exec: Script not found: Looking at: '/nonexistent/msrs-script.lua'"), "{}", err);
    }
}
