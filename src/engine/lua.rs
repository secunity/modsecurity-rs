//! Port of `src/engine/lua.cc`, `src/engine/lua.h`.
//!
//! The Lua engine behind `SecRuleScript` and the `exec` action. A script is
//! compiled once when the rules are loaded ([`Lua::load`]) and kept as Lua
//! bytecode (`lua_dump`); every run ([`Lua::run`]) loads that bytecode into
//! a fresh Lua state, runs the chunk and calls its `main` function. Scripts
//! reach the transaction through the `m` table: `m.log`, `m.getvar`,
//! `m.getvars` and `m.setvar`.
//!
//! The C API calls of the C++ code are expressed with the `mlua` crate
//! (Lua 5.4, the version the C++ reference build uses). Lua errors are
//! caught with Lua's own `pcall` so that the error object reaches us
//! untouched (mlua's own calls would append a stack traceback), and the
//! `luaL_check*` argument errors of the C API are reproduced by hand.
//! Without the `lua` feature the engine behaves like the C++ build without
//! `WITH_LUA`.

use crate::transaction::Transaction;

#[cfg(feature = "lua")]
pub use self::with_lua::Lua;
#[cfg(not(feature = "lua"))]
pub use self::without_lua::Lua;

/// `Lua::isCompatible` shared by both builds: the script must be a `.lua`
/// file that compiles.
fn is_compatible_impl(script: &str, l: &mut Lua, error: &mut String) -> bool {
    if cfg!(not(feature = "lua")) {
        *error = "Lua support was not enabled.".to_string();
        return false;
    }
    if !script.ends_with(".lua") {
        *error = format!("Expecting a Lua script: {}", script);
        return false;
    }
    if let Err(err) = l.load(script) {
        *error = format!("Problems load script: {}", err);
        return false;
    }
    true
}

#[cfg(not(feature = "lua"))]
mod without_lua {
    use super::Transaction;

    /// `Lua` (built without `WITH_LUA`).
    #[derive(Debug, Default)]
    pub struct Lua {
        pub script_name: String,
    }

    impl Lua {
        pub fn new() -> Self {
            Self::default()
        }

        /// `load`
        pub fn load(&mut self, _script: &str) -> Result<(), String> {
            Err("Lua support was not enabled.".to_string())
        }

        /// `run`
        pub fn run(&self, t: &mut Transaction<'_>, _s: &[u8]) -> i32 {
            crate::ms_dbg_a!(t, 9, "Lua support was not enabled.");
            0
        }

        /// `isCompatible`
        pub fn is_compatible(script: &str, l: &mut Lua, error: &mut String) -> bool {
            super::is_compatible_impl(script, l, error)
        }
    }
}

#[cfg(feature = "lua")]
mod with_lua {
    use mlua::chunk::ChunkMode;
    use mlua::{Function, IntoLuaMulti, LightUserData, MultiValue, Table, Value};

    use super::Transaction;
    use crate::actions::transformations::transformation;
    use crate::collection::collection::Collection;
    use crate::utils::string::{to_hex_if_needed, toupper_str};
    use crate::variables::variable::{string_match_resolve, string_match_resolve_multi};

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

    /// `Lua`
    #[derive(Debug, Default)]
    pub struct Lua {
        /// `m_blob` (the C++ `LuaScriptBlob`): the compiled script.
        blob: Vec<u8>,
        pub script_name: String,
    }

    /// The part of a C string the C API sees (`const char *` up to the
    /// first NUL).
    fn cstr(s: &[u8]) -> &[u8] {
        match s.iter().position(|&c| c == 0) {
            Some(p) => &s[..p],
            None => s,
        }
    }

    fn lossy(s: &[u8]) -> String {
        String::from_utf8_lossy(s).into_owned()
    }

    /// The message of an error raised by one of our callbacks (or by mlua).
    fn mlua_error_text(e: &mlua::Error) -> String {
        match e {
            mlua::Error::RuntimeError(s) | mlua::Error::MemoryError(s) => s.clone(),
            mlua::Error::SyntaxError { message, .. } => message.clone(),
            mlua::Error::CallbackError { cause, .. } => mlua_error_text(cause),
            mlua::Error::WithContext { cause, .. } => mlua_error_text(cause),
            other => other.to_string(),
        }
    }

    /// `lua_tostring(L, -1)`: strings and numbers (converted the way Lua
    /// does); `None` (a NULL pointer) for anything else. Errors raised by
    /// our callbacks are strings in C++ (`luaL_error`).
    fn lua_tostring(lua: &mlua::Lua, v: Value) -> Option<Vec<u8>> {
        match v {
            Value::String(s) => Some(cstr(&s.as_bytes()).to_vec()),
            Value::Integer(_) | Value::Number(_) => {
                lua.coerce_string(v).ok().flatten().map(|s| cstr(&s.as_bytes()).to_vec())
            }
            Value::Error(e) => Some(mlua_error_text(&e).into_bytes()),
            _ => None,
        }
    }

    /// `lua_type`
    fn lua_type(v: Option<&Value>) -> i32 {
        match v {
            None => -1,
            Some(Value::Nil) => 0,
            Some(Value::Boolean(_)) => 1,
            Some(Value::LightUserData(_)) => 2,
            Some(Value::Integer(_)) | Some(Value::Number(_)) => 3,
            Some(Value::String(_)) => 4,
            Some(Value::Table(_)) => 5,
            Some(Value::Function(_)) => 6,
            Some(Value::Thread(_)) => 8,
            Some(_) => 7,
        }
    }

    /// The type name `luaL_typeerror` reports.
    fn type_error_name(v: Option<&Value>) -> &'static str {
        match v {
            None => "no value",
            Some(Value::Nil) => "nil",
            Some(Value::Boolean(_)) => "boolean",
            Some(Value::LightUserData(_)) => "light userdata",
            Some(Value::Integer(_)) | Some(Value::Number(_)) => "number",
            Some(Value::String(_)) => "string",
            Some(Value::Table(_)) => "table",
            Some(Value::Function(_)) => "function",
            Some(Value::Thread(_)) => "thread",
            Some(_) => "userdata",
        }
    }

    /// `luaL_where(L, level)`: `"chunk:line: "` of the function at `level`,
    /// or nothing when it has no line information (e.g. a C function).
    fn lua_where(lua: &mlua::Lua, level: usize) -> String {
        lua.inspect_stack(level, |d| {
            let line = d.current_line();
            let src = d.source().short_src.map(|s| s.into_owned());
            match (line, src) {
                (Some(line), Some(src)) if line > 0 => format!("{}:{}: ", src, line),
                _ => String::new(),
            }
        })
        .unwrap_or_default()
    }

    /// `luaL_argerror`, raised as a Lua error (`luaL_error` adds the
    /// location of the calling Lua code). The function the script called is
    /// the `WRAPPER` closure, one level above the Rust callback: its name
    /// and its caller's location are the ones the C++ messages show. (Only
    /// a tail call such as `return m.log()` differs: the wrapper replaces
    /// the calling frame, so no location is shown for it.)
    fn arg_error(lua: &mlua::Lua, mut arg: i32, extramsg: &str) -> mlua::Error {
        let names = lua.inspect_stack(1, |d| {
            let n = d.names();
            (n.name.map(|s| s.into_owned()), n.name_what)
        });
        let msg = match names {
            None => format!("bad argument #{} ({})", arg, extramsg),
            Some((name, name_what)) => {
                let mut msg = None;
                if name_what == Some("method") {
                    // do not count 'self'
                    arg -= 1;
                    if arg == 0 {
                        msg =
                            Some(format!("calling '{}' on bad self ({})", name.clone().unwrap_or_default(), extramsg));
                    }
                }
                // (`pushglobalfuncname` finds nothing: the `m` functions
                // are not in `package.loaded`.)
                msg.unwrap_or_else(|| {
                    format!("bad argument #{} to '{}' ({})", arg, name.unwrap_or_else(|| "?".to_string()), extramsg)
                })
            }
        };
        mlua::Error::RuntimeError(format!("{}{}", lua_where(lua, 2), msg))
    }

    /// `luaL_typeerror`, raised as a Lua error.
    fn type_error(lua: &mlua::Lua, arg: i32, expected: &str, v: Option<&Value>) -> mlua::Error {
        let meta_name = match v {
            Some(Value::Table(t)) => {
                t.metatable().and_then(|mt| mt.raw_get::<Value>("__name").ok()).and_then(|n| match n {
                    Value::String(s) => Some(lossy(&s.as_bytes())),
                    _ => None,
                })
            }
            _ => None,
        };
        let typearg = meta_name.unwrap_or_else(|| type_error_name(v).to_string());
        arg_error(lua, arg, &format!("{} expected, got {}", expected, typearg))
    }

    /// `luaL_checkstring`: strings and numbers (converted); the result is
    /// the C string (up to the first NUL).
    fn check_string(lua: &mlua::Lua, v: Option<&Value>, arg: i32) -> mlua::Result<Vec<u8>> {
        match v {
            Some(Value::String(s)) => Ok(cstr(&s.as_bytes()).to_vec()),
            Some(n @ (Value::Integer(_) | Value::Number(_))) => match lua.coerce_string(n.clone())? {
                Some(s) => Ok(cstr(&s.as_bytes()).to_vec()),
                None => Err(type_error(lua, arg, "string", v)),
            },
            _ => Err(type_error(lua, arg, "string", v)),
        }
    }

    /// `luaL_checknumber`: numbers and strings convertible to numbers.
    fn check_number(lua: &mlua::Lua, v: Option<&Value>, arg: i32) -> mlua::Result<f64> {
        match v {
            Some(Value::Integer(i)) => Ok(*i as f64),
            Some(Value::Number(n)) => Ok(*n),
            Some(s @ Value::String(_)) => match lua.coerce_number(s.clone())? {
                Some(n) => Ok(n),
                None => Err(type_error(lua, arg, "number", v)),
            },
            _ => Err(type_error(lua, arg, "number", v)),
        }
    }

    impl Lua {
        pub fn new() -> Self {
            Self::default()
        }

        /// A Lua state with all the standard libraries (`luaL_newstate` +
        /// `luaL_openlibs`).
        fn new_state() -> mlua::Lua {
            // SAFETY: `unsafe_new` loads every standard library, including
            // `debug` (as `luaL_openlibs` does), and allows loading binary
            // chunks. The scripts are part of the trusted configuration and
            // the only binary chunk loaded is the one `load` produced.
            unsafe { mlua::Lua::unsafe_new() }
        }

        /// `load`: compiles `script` (`luaL_loadfile`) and keeps its
        /// bytecode (`lua_dump`).
        pub fn load(&mut self, script: &str) -> Result<(), String> {
            let lua = Self::new_state();
            self.script_name = script.to_string();

            let compiled = load_file(&lua, script).map_err(|luaerr| {
                // Sic: the C++ message has no closing quote.
                let mut err = format!("Failed to compile script '{}", script);
                if let Some(e) = luaerr {
                    err.push_str(": ");
                    err.push_str(&e);
                }
                err.push('.');
                err
            })?;
            // As in C++, the dump is appended to the blob.
            self.blob.extend_from_slice(&compiled.dump(false));
            Ok(())
        }

        /// `isCompatible`
        pub fn is_compatible(script: &str, l: &mut Lua, error: &mut String) -> bool {
            super::is_compatible_impl(script, l, error)
        }

        /// `run`: runs the script with `s` as the argument of `main` (none
        /// when empty). Returns 1 when `main` returned a non empty string
        /// (or number), 0 otherwise or on errors.
        pub fn run(&self, t: &mut Transaction<'_>, s: &[u8]) -> i32 {
            let t: &Transaction<'_> = t;
            let lua = Self::new_state();
            match self.run_in(&lua, t, s) {
                Ok(ret) => ret,
                Err(e) => {
                    // Failures of the Lua API itself (e.g. out of memory).
                    crate::ms_dbg_a!(
                        t,
                        2,
                        "Failed to execute lua script: {} - {}",
                        self.script_name,
                        mlua_error_text(&e)
                    );
                    0
                }
            }
        }

        fn run_in(&self, lua: &mlua::Lua, t: &Transaction<'_>, s: &[u8]) -> mlua::Result<i32> {
            lua.scope(|scope| {
                let globals = lua.globals();

                // luaL_newmetatable(L, "luaL_msc"): the metatable stays on
                // the C stack and later becomes the `modsec` global.
                let msc: Table = lua.create_table()?;
                msc.set("__name", "luaL_msc")?;
                lua.set_named_registry_value("luaL_msc", &msc)?;

                let m = lua.create_table()?;
                globals.set("__transaction", LightUserData(t as *const Transaction<'_> as *mut std::ffi::c_void))?;
                // The C functions of the C++ code raise their errors (bad
                // arguments) as strings with luaL_error. Errors returned by
                // mlua callbacks are userdata, so each function is wrapped
                // in a small Lua function that re-raises them as strings
                // (see `arg_error` for how the message is built).
                let wrap: Function = lua.load(WRAPPER).set_name("=m").eval()?;
                macro_rules! register {
                    ($name:literal, $f:ident) => {{
                        let imp = scope.create_function(|lua, args: MultiValue| {
                            match $f(lua, t, args).and_then(|r| r.into_lua_multi(lua)) {
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
                        crate::ms_dbg_a!(t, 2, "{}", msg);
                        return Ok(0);
                    }
                };

                let mut res = pcall.call::<MultiValue>(chunk)?.into_iter();
                if !matches!(res.next(), Some(Value::Boolean(true))) {
                    let mut e = format!("Failed to execute lua script: {} (before main)", self.script_name);
                    if let Some(luaerr) = lua_tostring(lua, res.next().unwrap_or(Value::Nil)) {
                        e.push_str(" - ");
                        e.push_str(&lossy(&luaerr));
                    }
                    crate::ms_dbg_a!(t, 2, "{}", e);
                    return Ok(0);
                }

                // lua_setglobal(L, "modsec") pops what is left on the stack:
                // the "luaL_msc" metatable.
                globals.set("modsec", msc)?;

                let main: Value = globals.get("main")?;

                crate::ms_dbg_a!(t, 9, "{}", lossy(s));

                // Put the parameter on the stack.
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
                    crate::ms_dbg_a!(t, 2, "{}", e);
                    return Ok(0);
                }

                // One result, as lua_pcall(L, nargs, 1, 0) asks for.
                let lua_ret = lua_tostring(lua, res.next().unwrap_or(Value::Nil)).unwrap_or_default();

                crate::ms_dbg_a!(t, 9, "Returning from lua script: {}", lossy(&lua_ret));

                Ok(if lua_ret.is_empty() { 0 } else { 1 })
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

        // skipcomment()
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
                // Add newline to correct line numbers.
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

    /// `m.log(level, text)`
    fn log(lua: &mlua::Lua, t: &Transaction<'_>, args: MultiValue) -> mlua::Result<()> {
        // Retrieve parameters.
        let level = check_number(lua, args.front(), 1)? as i32;
        let text = check_string(lua, args.get(1), 2)?;
        // Log message.
        crate::ms_dbg_a!(t, level, "{}", lossy(&text));
        Ok(())
    }

    /// `m.getvar(name [, transformations])`
    fn getvar(lua: &mlua::Lua, t: &Transaction<'_>, args: MultiValue) -> mlua::Result<MultiValue> {
        // Retrieve parameters.
        let varname = check_string(lua, args.front(), 1)?;

        let mut var = match string_match_resolve(t, &lossy(&varname)) {
            Ok(v) => v,
            Err(_) => {
                crate::ms_dbg_a!(t, 2, "Lua: m.getvar(): unknown variable: {}.", to_hex_if_needed(&varname, false));
                return Ok(MultiValue::from_iter([Value::Nil]));
            }
        };
        apply_transformations(lua, t, args.get(1), &mut var)?;

        if var.is_empty() {
            // Sic: C++ pushes nil but returns 0 results.
            return Ok(MultiValue::new());
        }

        Ok(MultiValue::from_iter([Value::String(lua.create_string(&var)?)]))
    }

    /// `m.getvars(name)`: a list of `{ name = ..., value = ... }`.
    fn getvars(lua: &mlua::Lua, t: &Transaction<'_>, args: MultiValue) -> mlua::Result<Table> {
        // Retrieve parameters.
        let varname = check_string(lua, args.front(), 1)?;

        let mut l = Vec::new();
        if string_match_resolve_multi(t, &lossy(&varname), &mut l).is_err() {
            crate::ms_dbg_a!(t, 2, "Lua: m.getvars(): unknown variable: {}.", to_hex_if_needed(&varname, false));
            return lua.create_table();
        }

        let list = lua.create_table()?;
        for (idx, i) in l.iter().enumerate() {
            let entry = lua.create_table()?;
            entry.set("name", lua.create_string(i.key_with_collection())?)?;
            entry.set("value", lua.create_string(i.value())?)?;
            list.set(idx + 1, entry)?;
        }
        Ok(list)
    }

    /// `m.setvar("collection.name", value)`
    fn setvar(lua: &mlua::Lua, t: &Transaction<'_>, args: MultiValue) -> mlua::Result<()> {
        if args.len() != 2 {
            crate::ms_dbg_a!(t, 8, "m.setvar: Failed m.setvar funtion must has 2 arguments");
            // The C++ function returns -1 here; to the caller that is no
            // value.
            return Ok(());
        }
        let var_value = check_string(lua, args.get(1), 2)?;
        let var_name = check_string(lua, args.front(), 1)?;

        let Some(pos) = var_name.iter().position(|&c| c == b'.') else {
            crate::ms_dbg_a!(
                t,
                8,
                "m.setvar: Must specify a collection using dot character - ie m.setvar(tx.myvar,mydata)"
            );
            return Ok(());
        };
        let collection = toupper_str(&lossy(&var_name[..pos]));
        let variable_name = &var_name[pos + 1..];

        let c = &t.collections;
        let web_app_id = Some(t.rules.properties.sec_web_app_id.value.as_bytes());
        match collection.as_str() {
            "TX" => {
                c.tx_collection.store_or_update_first(variable_name, &var_value);
            }
            "IP" => {
                c.ip_collection.store_or_update_first_c(variable_name, &c.ip_collection_key, web_app_id, &var_value);
            }
            "GLOBAL" => {
                c.global_collection.store_or_update_first_c(
                    variable_name,
                    &c.global_collection_key,
                    web_app_id,
                    &var_value,
                );
            }
            "RESOURCE" => {
                c.resource_collection.store_or_update_first_c(
                    variable_name,
                    &c.resource_collection_key,
                    web_app_id,
                    &var_value,
                );
            }
            "SESSION" => {
                c.session_collection.store_or_update_first_c(
                    variable_name,
                    &c.session_collection_key,
                    web_app_id,
                    &var_value,
                );
            }
            "USER" => {
                c.user_collection.store_or_update_first_c(
                    variable_name,
                    &c.user_collection_key,
                    web_app_id,
                    &var_value,
                );
            }
            _ => {}
        }
        Ok(())
    }

    /// `applyTransformations`: the second argument of `m.getvar`, a
    /// transformation name or a list of them.
    fn apply_transformations(
        lua: &mlua::Lua,
        t: &Transaction<'_>,
        idx: Option<&Value>,
        var: &mut Vec<u8>,
    ) -> mlua::Result<()> {
        match idx {
            // lua_isuserdata (mlua errors are userdata too) or lua_isnoneornil.
            None | Some(Value::Nil | Value::LightUserData(_) | Value::UserData(_) | Value::Error(_)) => Ok(()),
            Some(Value::Table(tbl)) => {
                let n = tbl.raw_len();
                for i in 1..=n {
                    let item: Value = tbl.raw_get(i)?;
                    let name = check_string(lua, Some(&item), -1)?;

                    // A "none" means start over
                    if name == b"none" {
                        continue;
                    }

                    // FIXME (C++): transformation is not yet returning null,
                    // so the "Invalid transformation function" branch of the
                    // C++ code is never taken.
                    let tfn = transformation::instantiate(&format!("t:{}", lossy(&name)));
                    tfn.transform(var, Some(t));
                }
                Ok(())
            }
            Some(v @ (Value::String(_) | Value::Integer(_) | Value::Number(_))) => {
                let name = check_string(lua, Some(v), 2)?;
                let tfn = transformation::instantiate(&format!("t:{}", lossy(&name)));
                tfn.transform(var, Some(t));
                Ok(())
            }
            other => {
                // Sic: the C++ code passes the stack index (2) to
                // lua_typename, which names type 2: "userdata".
                crate::ms_dbg_a!(
                    t,
                    8,
                    "SecRuleScript: Transformation parameter must be a transformation name or array of \
                     transformation names, but found userdata (type {})",
                    lua_type(other)
                );
                Ok(())
            }
        }
    }
}

#[cfg(all(test, feature = "lua"))]
mod tests {
    use super::Lua;
    use crate::collection::collection::Collection;
    use crate::modsecurity::ModSecurity;
    use crate::transaction::Transaction;
    use crate::variables::test_support::rules_with_log;

    const DATA: &str = "test/test-cases/data";

    fn loaded(name: &str) -> Lua {
        let mut l = Lua::new();
        let mut err = String::new();
        let path = format!("{}/{}", DATA, name);
        assert!(Lua::is_compatible(&path, &mut l, &mut err), "{}", err);
        assert_eq!(l.script_name, path);
        l
    }

    /// Writes `code` to a temporary `.lua` file.
    fn temp_script(name: &str, code: &str) -> String {
        let dir = std::env::temp_dir().join(format!("msrs-lua-tests-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join(name);
        std::fs::write(&p, code).unwrap();
        p.to_string_lossy().into_owned()
    }

    #[test]
    fn is_compatible_errors() {
        let mut l = Lua::new();
        let mut err = String::new();
        assert!(!Lua::is_compatible("script.txt", &mut l, &mut err));
        assert_eq!(err, "Expecting a Lua script: script.txt");

        assert!(!Lua::is_compatible("/nonexistent/x.lua", &mut l, &mut err));
        assert_eq!(
            err,
            "Problems load script: Failed to compile script '/nonexistent/x.lua: cannot open /nonexistent/x.lua: No such file or directory."
        );

        let p = temp_script("syntax.lua", "function main()\n  return (\nend\n");
        assert!(!Lua::is_compatible(&p, &mut l, &mut err));
        assert_eq!(
            err,
            format!("Problems load script: Failed to compile script '{p}: {p}:3: unexpected symbol near 'end'.")
        );
    }

    #[test]
    fn run_returns_main_result() {
        let ms = ModSecurity::new();
        let (rules, log) = rules_with_log();
        let mut t = Transaction::new(&ms, &rules, None);

        assert_eq!(loaded("match.lua").run(&mut t, b""), 1);
        assert!(log.lock().unwrap().contains("Returning from lua script: Lua script matched."));

        assert_eq!(loaded("test.lua").run(&mut t, b""), 0);
        assert!(log.lock().unwrap().contains(
            "Failed to execute lua script: test/test-cases/data/test.lua (main) - attempt to call a nil value"
        ));

        assert_eq!(loaded("match-log.lua").run(&mut t, b""), 1);
        assert!(log.lock().unwrap().contains("[9] echo 123\n"));

        // A shebang line is skipped and the argument reaches main.
        let p = temp_script("arg.lua", "#!/usr/bin/lua\nfunction main(a)\n  return a .. '!'\nend\n");
        let l = {
            let mut l = Lua::new();
            l.load(&p).unwrap();
            l
        };
        assert_eq!(l.run(&mut t, b"hello"), 1);
        assert!(log.lock().unwrap().contains("[9] hello\n"));
        assert!(log.lock().unwrap().contains("Returning from lua script: hello!"));

        // Numbers are returned as their string form.
        let p = temp_script("num.lua", "function main()\n  return 0\nend\n");
        let mut l = Lua::new();
        l.load(&p).unwrap();
        assert_eq!(l.run(&mut t, b""), 1);
        assert!(log.lock().unwrap().contains("Returning from lua script: 0\n"));

        // Errors.
        let p = temp_script("err.lua", "function main()\n  error('boom')\nend\n");
        let mut l = Lua::new();
        l.load(&p).unwrap();
        assert_eq!(l.run(&mut t, b""), 0);
        assert!(log.lock().unwrap().contains(&format!("[2] Failed to execute lua script: {p} (main) - {p}:2: boom\n")));
        let p = temp_script("err2.lua", "error({})\n");
        let mut l = Lua::new();
        l.load(&p).unwrap();
        assert_eq!(l.run(&mut t, b""), 0);
        assert!(log.lock().unwrap().contains(&format!("[2] Failed to execute lua script: {p} (before main)\n")));
        let p = temp_script("err3.lua", "function main()\n  m.log()\nend\n");
        let mut l = Lua::new();
        l.load(&p).unwrap();
        assert_eq!(l.run(&mut t, b""), 0);
        assert!(log.lock().unwrap().contains(&format!(
            "[2] Failed to execute lua script: {p} (main) - {p}:2: bad argument #1 to 'log' (number expected, got no value)\n"
        )));
        // `modsec` is the "luaL_msc" metatable.
        let p =
            temp_script("modsec.lua", "function main()\n  return getmetatable == nil and '' or modsec.__name\nend\n");
        let mut l = Lua::new();
        l.load(&p).unwrap();
        assert_eq!(l.run(&mut t, b""), 1);
        assert!(log.lock().unwrap().contains("Returning from lua script: luaL_msc\n"));
    }

    #[test]
    fn setvar_and_getvar() {
        let ms = ModSecurity::new();
        let (mut rules, log) = rules_with_log();
        rules.properties.sec_web_app_id.value = "app".to_string();
        let mut t = Transaction::new(&ms, &rules, None);
        // The persistent collections may live on disk (LMDB).
        let ip_key = format!("lua-test-{}", std::process::id());
        t.collections.ip_collection_key = ip_key.as_bytes().to_vec();

        assert_eq!(loaded("setvar.lua").run(&mut t, b""), 0);
        assert_eq!(t.collections.tx_collection.resolve_first(b"lua_set_var"), Some(b"2".to_vec()));
        assert_eq!(
            t.collections.ip_collection.resolve_first(format!("{}::app::lua_set_var", ip_key).as_bytes()),
            Some(b"2".to_vec())
        );

        assert_eq!(loaded("match-set.lua").run(&mut t, b""), 1);
        assert_eq!(t.collections.tx_collection.resolve_first(b"test"), Some(b"whee".to_vec()));

        t.collections.tx_collection.store_or_update_first(b"test", b"FELIPE");
        assert_eq!(loaded("match-getvar-transformation.lua").run(&mut t, b""), 1);
        assert!(log.lock().unwrap().contains("Just fine."));
        assert_eq!(loaded("match-getvar-multi-transformations.lua").run(&mut t, b""), 1);
        assert!(log.lock().unwrap().contains("Whee. Working like a charm. That is what we have: FELIPE"));

        t.collections.tx_collection.store_or_update_first(b"test", b"2");
        assert_eq!(loaded("match-getvar.lua").run(&mut t, b""), 1);
        assert!(log.lock().unwrap().contains("Number is bigger than one."));

        // Unknown variables.
        assert_eq!(loaded("lua-getvar-unknown.lua").run(&mut t, b""), 0);
        assert!(log.lock().unwrap().contains("[2] Lua: m.getvar(): unknown variable: UNKNOWN_VARIABLE.\n"));
        assert!(log.lock().unwrap().contains("UNKNOWN_VARIABLE is not available from Lua."));
        assert_eq!(loaded("lua-getvars-rule.lua").run(&mut t, b""), 0);
        assert!(log.lock().unwrap().contains("[2] Lua: m.getvars(): unknown variable: RULE.\n"));
        assert!(log.lock().unwrap().contains("RULE from Lua: 0 value(s)."));

        // setvar argument checks.
        let p = temp_script("setvar-args.lua", "function main()\n  m.setvar('x')\n  m.setvar('novalue', 'v')\nend\n");
        let mut l = Lua::new();
        l.load(&p).unwrap();
        assert_eq!(l.run(&mut t, b""), 0);
        assert!(log.lock().unwrap().contains("[8] m.setvar: Failed m.setvar funtion must has 2 arguments\n"));
        assert!(
            log.lock().unwrap().contains(
                "[8] m.setvar: Must specify a collection using dot character - ie m.setvar(tx.myvar,mydata)\n"
            )
        );

        // Bad transformation parameter type.
        let p = temp_script("tfn.lua", "function main()\n  m.getvar('tx.test', true)\nend\n");
        let mut l = Lua::new();
        l.load(&p).unwrap();
        l.run(&mut t, b"");
        assert!(log.lock().unwrap().contains(
            "[8] SecRuleScript: Transformation parameter must be a transformation name or array of transformation names, but found userdata (type 1)\n"
        ));
    }

    /// The same script was run through the C++ reference build; the
    /// expected lines are its debug log.
    #[test]
    fn callback_errors_match_cpp() {
        let ms = ModSecurity::new();
        let (rules, log) = rules_with_log();
        let mut t = Transaction::new(&ms, &rules, None);
        let p = temp_script(
            "probe.lua",
            r#"function main()
  m.log(1, "count=" .. select('#', m.getvar('tx.nothere')) .. " modsec=" .. tostring(modsec.__name) .. " tr=" .. tostring(__transaction ~= nil))
  m.setvar('x')
  local ok, e = pcall(m.setvar, 'tx.a', {})
  m.log(1, "E1:" .. tostring(e))
  ok, e = pcall(m.getvar, 'tx.a', {{}})
  m.log(1, "E2:" .. tostring(e))
  ok, e = pcall(m.log, "abc", "x")
  m.log(1, "E3:" .. tostring(e))
  local f = m.log
  ok, e = pcall(function() f() end)
  m.log(1, "E4:" .. tostring(e))
  m.log("2", 12.0)
  return 1.5
end
"#,
        );
        let mut l = Lua::new();
        l.load(&p).unwrap();
        let ret = l.run(&mut t, b"");
        let got = log.lock().unwrap().clone();
        assert_eq!(ret, 1, "{}", got);
        let expected = format!(
            "[1] count=0 modsec=luaL_msc tr=true
[8] m.setvar: Failed m.setvar funtion must has 2 arguments
[1] E1:bad argument #2 to '?' (string expected, got table)
[1] E2:bad argument #-1 to '?' (string expected, got table)
[1] E3:bad argument #1 to '?' (number expected, got string)
[1] E4:{p}:11: bad argument #1 to 'f' (number expected, got no value)
[2] 12.0
[9] Returning from lua script: 1.5
"
        );
        assert!(got.contains(&expected), "{}", got);
    }

    #[test]
    fn getvars_lists_values() {
        let ms = ModSecurity::new();
        let (rules, log) = rules_with_log();
        let mut t = Transaction::new(&ms, &rules, None);
        t.process_uri(b"/?a=1&b=2", b"GET", b"1.1");
        assert_eq!(loaded("match-getvars-args.lua").run(&mut t, b""), 0);
        assert!(log.lock().unwrap().contains("ARGS count read =2"));
        assert_eq!(loaded("match-getvars.lua").run(&mut t, b""), 0);
        let s = log.lock().unwrap().clone();
        assert!(s.contains("[\"name\"] = QUERY_STRING,") && s.contains("[\"value\"] = a=1&b=2,"), "{}", s);
    }
}

#[cfg(all(test, not(feature = "lua")))]
mod tests {
    use super::Lua;
    use crate::modsecurity::ModSecurity;
    use crate::transaction::Transaction;
    use crate::variables::test_support::rules_with_log;

    #[test]
    fn lua_disabled() {
        let mut l = Lua::new();
        let mut err = String::new();
        assert!(!Lua::is_compatible("test/test-cases/data/match.lua", &mut l, &mut err));
        assert_eq!(err, "Lua support was not enabled.");
        assert_eq!(l.load("x.lua"), Err("Lua support was not enabled.".to_string()));
        let ms = ModSecurity::new();
        let (rules, log) = rules_with_log();
        let mut t = Transaction::new(&ms, &rules, None);
        assert_eq!(l.run(&mut t, b""), 0);
        assert!(log.lock().unwrap().contains("[9] Lua support was not enabled.\n"));
    }
}
