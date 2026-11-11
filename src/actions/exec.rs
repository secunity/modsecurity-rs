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
        let mut err = String::new();
        self.script = find_resource(&self.base.parser_payload, "", &mut err);
        if self.script.is_empty() {
            return Err(format!("exec: Script not found: {}", err));
        }
        if !Lua::is_compatible(&self.script, &mut self.lua, &mut err) {
            return Err(format!("exec: {}", err));
        }
        Ok(())
    }

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, _rm: &mut RuleMessage<'_>) -> bool {
        crate::ms_dbg_a!(t, 8, "Running script... {}", self.script);
        self.lua.run(t, b"");
        true
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
