//! A `SecRuleScript`: a rule that runs a Lua script.

use crate::engine::lua::Lua;
use crate::rule::Rule;
use crate::rule::message::RuleMessage;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct Script {
    pub name: String,
    pub lua: Lua,
}

impl Script {
    pub fn new(name: &str) -> Self {
        Script { name: name.to_string(), lua: Lua::new() }
    }

    /// Loads (compiles) the script.
    pub fn init(&mut self) -> Result<(), String> {
        let name = self.name.clone();
        self.lua.load(&name)
    }

    /// Runs the script; the rule matches when the script's `main` returns
    /// a non empty string (or number).
    pub fn evaluate<'a>(&'a self, rule: &'a Rule, t: &mut Transaction<'a>, rm: &mut RuleMessage<'a>) -> bool {
        crate::ms_dbg_a!(t, 4, " Executing script: {}.", self.name);
        let contains_block = rule.execute_actions_independent_of_chained_rule_result(t, rm);
        let ret = self.lua.run(t, b"");
        if ret {
            rule.execute_actions_after_full_match(t, contains_block, rm);
        }
        ret
    }
}
