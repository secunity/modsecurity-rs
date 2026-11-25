//! The Lua engine behind `SecRuleScript` and the `exec` action. A script is
//! compiled once when the rules are loaded ([`Lua::load`]) and kept as Lua
//! bytecode (`lua_dump`); every run ([`Lua::run`]) loads that bytecode into
//! a fresh Lua state, runs the chunk and calls its `main` function. Scripts
//! reach the transaction through the `m` table: `m.log`, `m.getvar`,
//! `m.getvars` and `m.setvar`.
//!
//! Lua is reached through the `mlua` crate (Lua 5.4). Lua errors are
//! caught with Lua's own `pcall` so that the error object reaches us
//! untouched (mlua's own calls would append a stack traceback), and the
//! `luaL_check*` argument errors of Lua's C API are reproduced by hand, so
//! that the messages are the ones libmodsecurity writes to the debug log.
//! Without the `lua` feature no script can be loaded: "Lua support was not
//! enabled."
//!
//! `engine.rs` loads and runs a script; `api.rs` has the `m.*` functions;
//! `lauxlib.rs` reproduces the argument checks and the messages of Lua's C
//! API (`luaL_check*`, `luaL_argerror`, `lua_tostring`, ...).

#[cfg(feature = "lua")]
mod api;
#[cfg(not(feature = "lua"))]
mod disabled;
#[cfg(feature = "lua")]
mod engine;
#[cfg(feature = "lua")]
mod lauxlib;
#[cfg(all(test, feature = "lua"))]
mod tests;

#[cfg(not(feature = "lua"))]
pub use self::disabled::Lua;
#[cfg(feature = "lua")]
pub use self::engine::Lua;

impl Lua {
    /// An engine with `script` loaded. The script must be a `.lua` file
    /// that compiles.
    pub fn from_script(script: &str) -> Result<Lua, String> {
        if cfg!(not(feature = "lua")) {
            return Err("Lua support was not enabled.".to_string());
        }
        if !script.ends_with(".lua") {
            return Err(format!("Expecting a Lua script: {}", script));
        }
        let mut l = Lua::new();
        l.load(script).map_err(|err| format!("Problems load script: {}", err))?;
        Ok(l)
    }
}
