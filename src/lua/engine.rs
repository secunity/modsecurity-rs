//! Compiling a script once and running it in a fresh Lua state.

use mlua::chunk::ChunkMode;
use mlua::{Function, IntoLuaMulti, MultiValue, Table, Value};
use std::cell::RefCell;

use super::api::{getvar, getvars, log, setvar};
use super::lauxlib::{lossy, lua_tostring, mlua_error_text};
use crate::transaction::Transaction;

// The `m.*` callbacks share the transaction (the `&mut` the engine
// passed in) through a `RefCell`. Borrow it only for the engine's reads
// and writes, never across a Lua API call: an allocation can run a
// finalizer that calls `m.*` again.
pub(super) type ScriptTransaction<'scope, 'rules> = RefCell<&'scope mut Transaction<'rules>>;

/// Wraps the Rust implementation of an `m.*` function (which returns
/// `true, results...` or `false, message`) so that its errors are raised
/// as plain strings, like `luaL_error` does.
const WRAPPER: &str = r#"
local error = error
local function check(ok, ...)
  if not ok then
error((...), 0)
  end
  return ...
end
return function(impl)
  return function(...)
return check(impl(...))
  end
end
"#;

/// The Lua engine: one compiled script.
#[derive(Debug, Default)]
pub struct Lua {
    /// The compiled script (Lua bytecode).
    blob: Vec<u8>,
    pub script_name: String,
}

impl Lua {
    pub fn new() -> Self {
        Self::default()
    }

    /// A Lua state with all the standard libraries (`luaL_newstate` +
    /// `luaL_openlibs`).
    fn new_state() -> mlua::Lua {
        modsecurity_native::lua::new_state()
    }

    /// Compiles `script` (`luaL_loadfile`) and keeps its bytecode
    /// (`lua_dump`).
    pub fn load(&mut self, script: &str) -> Result<(), String> {
        let lua = Self::new_state();
        self.script_name = script.to_string();

        let compiled = load_file(&lua, script).map_err(|luaerr| {
            let mut err = format!("Failed to compile script '{}'", script);
            if let Some(e) = luaerr {
                err.push_str(": ");
                err.push_str(&e);
            }
            err.push('.');
            err
        })?;
        self.blob.extend_from_slice(&compiled.dump(false));
        Ok(())
    }

    /// Runs the script with `s` as the argument of `main` (none when
    /// empty). Returns whether `main` returned a non empty string (or
    /// number); `false` on errors.
    pub fn run(&self, t: &mut Transaction<'_>, s: &[u8]) -> bool {
        let lua = Self::new_state();
        match self.run_in(&lua, t, s) {
            Ok(ret) => ret,
            Err(e) => {
                // Failures of the Lua API itself (e.g. out of memory).
                crate::ms_dbg!(t, 2, "Failed to execute lua script: {} - {}", self.script_name, mlua_error_text(&e));
                false
            }
        }
    }

    fn run_in(&self, lua: &mlua::Lua, t: &mut Transaction<'_>, s: &[u8]) -> mlua::Result<bool> {
        let t = RefCell::new(t);
        lua.scope(|scope| {
            let globals = lua.globals();

            // luaL_newmetatable(L, "luaL_msc"): the metatable stays on
            // the C stack and later becomes the `modsec` global.
            let msc: Table = lua.create_table()?;
            msc.set("__name", "luaL_msc")?;
            lua.set_named_registry_value("luaL_msc", &msc)?;

            let m = lua.create_table()?;
            // The errors of these functions (bad arguments) are raised
            // as strings, as luaL_error raises them. Errors returned by
            // mlua callbacks are userdata, so each function is wrapped
            // in a small Lua function that re-raises them as strings
            // (see `arg_error` for how the message is built).
            let wrap: Function = lua.load(WRAPPER).set_name("=m").eval()?;
            macro_rules! register {
                ($name:literal, $f:ident) => {{
                    let imp = scope.create_function(|lua, args: MultiValue| {
                        match $f(lua, &t, args).and_then(|r| r.into_lua_multi(lua)) {
                            Ok(mut v) => {
                                v.push_front(Value::Boolean(true));
                                Ok(v)
                            }
                            Err(e) => Ok(MultiValue::from_iter([
                                Value::Boolean(false),
                                Value::String(lua.create_string(mlua_error_text(&e))?),
                            ])),
                        }
                    })?;
                    m.set($name, wrap.call::<Function>(imp)?)?;
                }};
            }
            register!("log", log);
            register!("getvar", getvar);
            register!("getvars", getvars);
            register!("setvar", setvar);
            globals.set("m", m)?;

            // Lua's own pcall keeps the error object as is.
            let pcall: Function = globals.get("pcall")?;

            let chunk = match lua
                .load(self.blob.as_slice())
                .set_name(self.script_name.as_str())
                .set_mode(ChunkMode::Binary)
                .into_function()
            {
                Ok(f) => f,
                Err(e) => {
                    let mut msg = match &e {
                        mlua::Error::SyntaxError { .. } => "Syntax error. ".to_string(),
                        mlua::Error::MemoryError(_) => "Memory error. ".to_string(),
                        _ => format!("Failed to execute lua script: {}. ", self.script_name),
                    };
                    msg.push_str(&mlua_error_text(&e));
                    crate::ms_dbg!(&**t.borrow(), 2, "{}", msg);
                    return Ok(false);
                }
            };

            let mut res = pcall.call::<MultiValue>(chunk)?.into_iter();
            if !matches!(res.next(), Some(Value::Boolean(true))) {
                let mut e = format!("Failed to execute lua script: {} (before main)", self.script_name);
                if let Some(luaerr) = lua_tostring(lua, res.next().unwrap_or(Value::Nil)) {
                    e.push_str(" - ");
                    e.push_str(&lossy(&luaerr));
                }
                crate::ms_dbg!(&**t.borrow(), 2, "{}", e);
                return Ok(false);
            }

            // lua_setglobal(L, "modsec") pops what is left on the stack:
            // the "luaL_msc" metatable.
            globals.set("modsec", msc)?;

            let main: Value = globals.get("main")?;

            crate::ms_dbg!(&**t.borrow(), 9, "{}", lossy(s));

            let mut args = MultiValue::new();
            args.push_back(main);
            if !s.is_empty() {
                args.push_back(Value::String(lua.create_string(s)?));
            }
            let mut res = pcall.call::<MultiValue>(args)?.into_iter();
            if !matches!(res.next(), Some(Value::Boolean(true))) {
                let mut e = format!("Failed to execute lua script: {} (main)", self.script_name);
                if let Some(luaerr) = lua_tostring(lua, res.next().unwrap_or(Value::Nil)) {
                    e.push_str(" - ");
                    e.push_str(&lossy(&luaerr));
                }
                crate::ms_dbg!(&**t.borrow(), 2, "{}", e);
                return Ok(false);
            }

            // One result, as lua_pcall(L, nargs, 1, 0) asks for.
            let lua_ret = lua_tostring(lua, res.next().unwrap_or(Value::Nil)).unwrap_or_default();

            crate::ms_dbg!(&**t.borrow(), 9, "Returning from lua script: {}", lossy(&lua_ret));

            Ok(!lua_ret.is_empty())
        })
    }
}

/// `luaL_loadfile`: reads `script`, skipping a UTF-8 BOM and a first
/// line starting with `#`, and compiles it (text or binary). The error
/// is the Lua error message.
fn load_file(lua: &mlua::Lua, script: &str) -> Result<Function, Option<String>> {
    use std::io::Read;
    let errfile = |what: &str, e: std::io::Error| {
        Some(match e.raw_os_error() {
            Some(errno) if errno != 0 => {
                format!("cannot {} {}: {}", what, script, crate::utils::system::strerror(errno))
            }
            _ => format!("cannot {} {}", what, script),
        })
    };
    let mut f = std::fs::File::open(script).map_err(|e| errfile("open", e))?;
    let mut data = Vec::new();
    f.read_to_end(&mut data).map_err(|e| errfile("read", e))?;

    // A UTF-8 BOM and a first line starting with `#` are skipped, as
    // `skipcomment` of Lua's `lauxlib.c` does.
    let mut start = if data.starts_with(b"\xEF\xBB\xBF") { 3 } else { 0 };
    let mut skipped = false;
    if data.get(start) == Some(&b'#') {
        start = match data[start..].iter().position(|&c| c == b'\n') {
            Some(p) => start + p + 1,
            None => data.len(),
        };
        skipped = true;
    }
    let (code, mode) = if data.get(start) == Some(&0x1b) {
        // Binary file: the newline is not added.
        (data[start..].to_vec(), ChunkMode::Binary)
    } else {
        let mut code = Vec::with_capacity(data.len() - start + 1);
        if skipped {
            // A newline in place of the skipped line keeps the line
            // numbers right.
            code.push(b'\n');
        }
        code.extend_from_slice(&data[start..]);
        (code, ChunkMode::Text)
    };

    lua.load(code)
        .set_name(format!("@{}", script))
        .set_mode(mode)
        .into_function()
        .map_err(|e| Some(mlua_error_text(&e)))
}
