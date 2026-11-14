//! Lua states (through `mlua`, which is safe apart from this constructor).

/// A Lua state with all the standard libraries (`luaL_newstate` +
/// `luaL_openlibs`).
pub fn new_state() -> mlua::Lua {
    // SAFETY: `unsafe_new` loads every standard library, including `debug`
    // (as `luaL_openlibs` does), and allows loading binary chunks. The
    // scripts are part of the trusted configuration, and the engine only
    // loads binary chunks it produced itself (`lua_dump` of a loaded script).
    unsafe { mlua::Lua::unsafe_new() }
}
