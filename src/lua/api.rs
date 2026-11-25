//! The `m` table of a script: `m.log`, `m.getvar`, `m.getvars` and
//! `m.setvar`.

use mlua::{MultiValue, Table, Value};

use super::engine::ScriptTransaction;
use super::lauxlib::{check_number, check_string, lossy, lua_type};
use crate::actions::transformation;
use crate::utils::string::to_hex_if_needed;
use crate::variables::variable::{string_match_resolve, string_match_resolve_multi};

/// `m.log(level, text)`: writes `text` to the debug log at `level`.
pub(super) fn log(lua: &mlua::Lua, t: &ScriptTransaction<'_, '_>, args: MultiValue) -> mlua::Result<()> {
    // A level out of the range of a `u8` is the nearest bound.
    let level = check_number(lua, args.front(), 1)? as u8;
    let text = check_string(lua, args.get(1), 2)?;
    crate::ms_dbg!(&**t.borrow(), level, "{}", lossy(&text));
    Ok(())
}

/// `m.getvar(name [, transformations])`: the first value of a
/// variable, transformed.
pub(super) fn getvar(lua: &mlua::Lua, t: &ScriptTransaction<'_, '_>, args: MultiValue) -> mlua::Result<MultiValue> {
    let varname = check_string(lua, args.front(), 1)?;

    let mut var = match string_match_resolve(&t.borrow(), &lossy(&varname)) {
        Ok(v) => v,
        Err(_) => {
            crate::ms_dbg!(
                &**t.borrow(),
                2,
                "Lua: m.getvar(): unknown variable: {}.",
                to_hex_if_needed(&varname, false)
            );
            return Ok(MultiValue::from_iter([Value::Nil]));
        }
    };
    apply_transformations(lua, t, args.get(1), &mut var)?;

    if var.is_empty() {
        // Sic: no result for an empty value, not nil.
        return Ok(MultiValue::new());
    }

    Ok(MultiValue::from_iter([Value::String(lua.create_string(&var)?)]))
}

/// `m.getvars(name)`: a list of `{ name = ..., value = ... }`.
pub(super) fn getvars(lua: &mlua::Lua, t: &ScriptTransaction<'_, '_>, args: MultiValue) -> mlua::Result<Table> {
    let varname = check_string(lua, args.front(), 1)?;

    let mut l = Vec::new();
    if string_match_resolve_multi(&t.borrow(), &lossy(&varname), &mut l).is_err() {
        crate::ms_dbg!(&**t.borrow(), 2, "Lua: m.getvars(): unknown variable: {}.", to_hex_if_needed(&varname, false));
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

/// `m.setvar("collection.name", value)`: sets a `TX` or persistent
/// collection variable.
pub(super) fn setvar(lua: &mlua::Lua, t: &ScriptTransaction<'_, '_>, args: MultiValue) -> mlua::Result<()> {
    if args.len() != 2 {
        crate::ms_dbg!(&**t.borrow(), 8, "m.setvar: Failed m.setvar function must have 2 arguments");
        // Logged, and the script gets no value and no error.
        return Ok(());
    }
    let var_value = check_string(lua, args.get(1), 2)?;
    let var_name = check_string(lua, args.front(), 1)?;

    let Some(pos) = var_name.iter().position(|&c| c == b'.') else {
        crate::ms_dbg!(
            &**t.borrow(),
            8,
            "m.setvar: Must specify a collection using dot character - ie m.setvar(tx.myvar,mydata)"
        );
        return Ok(());
    };
    let collection = &var_name[..pos];
    let variable_name = &var_name[pos + 1..];

    let mut t = t.borrow_mut();
    if collection.eq_ignore_ascii_case(b"TX") {
        t.collections.tx.set(variable_name, var_value);
    } else if let Some(collection) = crate::collection::Persistent::parse(collection) {
        let stored =
            t.collections.persistent(collection).set(variable_name, t.rules.properties.web_app_id(), &var_value);
        t.stored(stored);
    }
    Ok(())
}

/// Applies the second argument of `m.getvar` to `var`: a
/// transformation name or a list of them.
pub(super) fn apply_transformations(
    lua: &mlua::Lua,
    t: &ScriptTransaction<'_, '_>,
    idx: Option<&Value>,
    var: &mut Vec<u8>,
) -> mlua::Result<()> {
    match idx {
        // No argument, nil or a userdata (`lua_isnoneornil`,
        // `lua_isuserdata`; mlua errors are userdata too): nothing to do.
        None | Some(Value::Nil | Value::LightUserData(_) | Value::UserData(_) | Value::Error(_)) => Ok(()),
        Some(Value::Table(tbl)) => {
            let n = tbl.raw_len();
            for i in 1..=n {
                let item: Value = tbl.raw_get(i)?;
                let name = check_string(lua, Some(&item), -1)?;

                // `none` is skipped: it does not undo the
                // transformations before it.
                if name == b"none" {
                    continue;
                }

                // An unknown transformation name is not an error: it
                // does nothing (see `Transformation::from_name`).
                let tfn = transformation::Transformation::from_name(&format!("t:{}", lossy(&name)));
                tfn.transform(var, Some(&t.borrow()));
            }
            Ok(())
        }
        Some(v @ (Value::String(_) | Value::Integer(_) | Value::Number(_))) => {
            let name = check_string(lua, Some(v), 2)?;
            let tfn = transformation::Transformation::from_name(&format!("t:{}", lossy(&name)));
            tfn.transform(var, Some(&t.borrow()));
            Ok(())
        }
        other => {
            // Sic: the message always names the type "userdata" (the
            // name of Lua type 2), whatever was found; the number is
            // the real type.
            crate::ms_dbg!(
                &**t.borrow(),
                8,
                "SecRuleScript: Transformation parameter must be a transformation name or array of \
                 transformation names, but found userdata (type {})",
                lua_type(other)
            );
            Ok(())
        }
    }
}
