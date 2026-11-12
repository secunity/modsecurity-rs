//! Port of `src/rule_script.h` / `src/rule_script.cc` (`SecRuleScript`).

use crate::engine::lua::Lua;
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct RuleScript {
    pub name: String,
    pub lua: Lua,
}

impl RuleScript {
    pub fn new(name: &str) -> Self {
        RuleScript { name: name.to_string(), lua: Lua::new() }
    }

    /// `init`: loads (compiles) the script.
    pub fn init(&mut self) -> Result<(), String> {
        let name = self.name.clone();
        self.lua.load(&name)
    }

    /// `RuleScript::evaluate`
    pub fn evaluate<'a>(
        &'a self,
        rule: &'a RuleWithActions,
        t: &mut Transaction<'a>,
        rm: &mut RuleMessage<'a>,
    ) -> bool {
        crate::ms_dbg_a!(t, 4, " Executing script: {}.", self.name);
        let contains_block = rule.execute_actions_independent_of_chained_rule_result(t, rm);
        let ret = self.lua.run(t, b"") != 0;
        if ret {
            rule.execute_actions_after_full_match(t, contains_block, rm);
        }
        ret
    }
}
