//! The Lua engine of a build without the `lua` feature.

use crate::transaction::Transaction;

/// The Lua engine of a build without the `lua` feature: no script can
/// be loaded.
#[derive(Debug, Default)]
pub struct Lua {
    pub script_name: String,
}

impl Lua {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fails: Lua support is not enabled.
    pub fn load(&mut self, _script: &str) -> Result<(), String> {
        Err("Lua support was not enabled.".to_string())
    }

    /// Logs that Lua support is not enabled and returns `false`.
    pub fn run(&self, t: &mut Transaction<'_>, _s: &[u8]) -> bool {
        crate::ms_dbg!(t, 9, "Lua support was not enabled.");
        false
    }
}

#[cfg(test)]
mod tests {
    use super::Lua;
    use crate::debug_log::test_support::rules_with_log;
    use crate::instance::ModSecurity;
    use crate::transaction::Transaction;

    #[test]
    fn lua_disabled() {
        assert_eq!(Lua::from_script("test/test-cases/data/match.lua").unwrap_err(), "Lua support was not enabled.");
        let mut l = Lua::new();
        assert_eq!(l.load("x.lua"), Err("Lua support was not enabled.".to_string()));
        let ms = ModSecurity::new();
        let (rules, log) = rules_with_log();
        let mut t = Transaction::new(&ms, &rules, None);
        assert!(!l.run(&mut t, b""));
        assert!(log.text().contains("[9] Lua support was not enabled.\n"));
    }
}
