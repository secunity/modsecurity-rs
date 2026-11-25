//! What Lua's C API (`lauxlib`) does for the functions it calls, reproduced
//! for the `m.*` functions: argument checks, the messages of their errors,
//! `lua_tostring`, `lua_type`.

use mlua::Value;

use modsecurity_compat::chars::c_str as cstr;

pub(super) fn lossy(s: &[u8]) -> String {
    String::from_utf8_lossy(s).into_owned()
}

/// The message of an error raised by one of our callbacks (or by mlua).
pub(super) fn mlua_error_text(e: &mlua::Error) -> String {
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
/// our callbacks are strings (see `WRAPPER`).
pub(super) fn lua_tostring(lua: &mlua::Lua, v: Value) -> Option<Vec<u8>> {
    match v {
        Value::String(s) => Some(cstr(&s.as_bytes()).to_vec()),
        Value::Integer(_) | Value::Number(_) => {
            lua.coerce_string(v).ok().flatten().map(|s| cstr(&s.as_bytes()).to_vec())
        }
        Value::Error(e) => Some(mlua_error_text(&e).into_bytes()),
        _ => None,
    }
}

/// The type code `lua_type` returns for `v` (-1 for no value).
pub(super) fn lua_type(v: Option<&Value>) -> i32 {
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
pub(super) fn type_error_name(v: Option<&Value>) -> &'static str {
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
pub(super) fn lua_where(lua: &mlua::Lua, level: usize) -> String {
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
/// and its caller's location are the ones `luaL_argerror` shows. (Only
/// a tail call such as `return m.log()` differs: the wrapper replaces
/// the calling frame, so no location is shown for it.)
pub(super) fn arg_error(lua: &mlua::Lua, mut arg: i32, extramsg: &str) -> mlua::Error {
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
                    msg = Some(format!("calling '{}' on bad self ({})", name.clone().unwrap_or_default(), extramsg));
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
pub(super) fn type_error(lua: &mlua::Lua, arg: i32, expected: &str, v: Option<&Value>) -> mlua::Error {
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
pub(super) fn check_string(lua: &mlua::Lua, v: Option<&Value>, arg: i32) -> mlua::Result<Vec<u8>> {
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
pub(super) fn check_number(lua: &mlua::Lua, v: Option<&Value>, arg: i32) -> mlua::Result<f64> {
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
