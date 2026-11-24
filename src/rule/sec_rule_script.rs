//! A `SecRuleScript`: a rule that runs a Lua script.

use crate::lua::Lua;

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
}
