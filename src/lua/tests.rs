use super::Lua;
use crate::debug_log::test_support::rules_with_log;
use crate::instance::ModSecurity;
use crate::transaction::Transaction;

const DATA: &str = "test/test-cases/data";

fn loaded(name: &str) -> Lua {
    let path = format!("{}/{}", DATA, name);
    let l = Lua::from_script(&path).unwrap();
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
fn finalizers_can_reenter_transaction_callbacks() {
    let ms = ModSecurity::new();
    let (rules, log) = rules_with_log();
    let mut t = Transaction::new(&ms, &rules, None);
    for i in 0..200 {
        t.collections.tx.set(format!("entry-{i}").as_bytes(), b"value".to_vec());
        t.vars.args.set(format!("arg-{i}").as_bytes(), b"value", 0);
    }
    let path = temp_script(
        "reentrant-finalizers.lua",
        r#"
        function main()
            collectgarbage('collect')
            collectgarbage('stop')
            local active, reentered, finalized = false, false, 0
            local function finalize()
                assert(m.getvar('TX.entry-0') == 'value')
                finalized = finalized + 1
                m.setvar('Tx.finalized', finalized)
                if active then reentered = true end
            end
            for i = 1, 1000 do
                local garbage = setmetatable({}, {__gc = finalize})
            end
            collectgarbage('incremental', 0, 200, 1)
            collectgarbage('restart')
            for i = 1, 30 do
                active = true
                local values = m.getvars('ARGS')
                active = false
                assert(#values >= 200)
            end
            collectgarbage('collect')
            assert(finalized == 1000, 'finalizers failed')
            assert(reentered, 'no finalizer ran inside a callback')
            assert(m.getvar('TX.finalized') == '1000')
            local ok = pcall(m.getvar, {})
            assert(not ok)
            m.setvar('tx.after_error', 'still usable')
            return 'ok'
        end
    "#,
    );
    let script = Lua::from_script(&path).unwrap();
    assert!(script.run(&mut t, b""), "{}", log.text());
    assert_eq!(t.collections.tx.get(b"finalized"), Some(&b"1000"[..]));
    assert_eq!(t.collections.tx.get(b"after_error"), Some(&b"still usable"[..]));
    std::fs::remove_file(path).unwrap();
}

#[test]
fn is_compatible_errors() {
    assert_eq!(Lua::from_script("script.txt").unwrap_err(), "Expecting a Lua script: script.txt");

    assert_eq!(
        Lua::from_script("/nonexistent/x.lua").unwrap_err(),
        "Problems load script: Failed to compile script '/nonexistent/x.lua': cannot open /nonexistent/x.lua: No such file or directory."
    );

    let p = temp_script("syntax.lua", "function main()\n  return (\nend\n");
    assert_eq!(
        Lua::from_script(&p).unwrap_err(),
        format!("Problems load script: Failed to compile script '{p}': {p}:3: unexpected symbol near 'end'.")
    );
}

#[test]
fn run_returns_main_result() {
    let ms = ModSecurity::new();
    let (rules, log) = rules_with_log();
    let mut t = Transaction::new(&ms, &rules, None);

    assert!(loaded("match.lua").run(&mut t, b""));
    assert!(log.text().contains("Returning from lua script: Lua script matched."));

    assert!(!loaded("test.lua").run(&mut t, b""));
    assert!(
        log.text().contains(
            "Failed to execute lua script: test/test-cases/data/test.lua (main) - attempt to call a nil value"
        )
    );

    assert!(loaded("match-log.lua").run(&mut t, b""));
    assert!(log.text().contains("[9] echo 123\n"));

    // A shebang line is skipped and the argument reaches main.
    let p = temp_script("arg.lua", "#!/usr/bin/lua\nfunction main(a)\n  return a .. '!'\nend\n");
    let l = {
        let mut l = Lua::new();
        l.load(&p).unwrap();
        l
    };
    assert!(l.run(&mut t, b"hello"));
    assert!(log.text().contains("[9] hello\n"));
    assert!(log.text().contains("Returning from lua script: hello!"));

    // Numbers are returned as their string form.
    let p = temp_script("num.lua", "function main()\n  return 0\nend\n");
    let mut l = Lua::new();
    l.load(&p).unwrap();
    assert!(l.run(&mut t, b""));
    assert!(log.text().contains("Returning from lua script: 0\n"));

    // Errors.
    let p = temp_script("err.lua", "function main()\n  error('boom')\nend\n");
    let mut l = Lua::new();
    l.load(&p).unwrap();
    assert!(!l.run(&mut t, b""));
    assert!(log.text().contains(&format!("[2] Failed to execute lua script: {p} (main) - {p}:2: boom\n")));
    let p = temp_script("err2.lua", "error({})\n");
    let mut l = Lua::new();
    l.load(&p).unwrap();
    assert!(!l.run(&mut t, b""));
    assert!(log.text().contains(&format!("[2] Failed to execute lua script: {p} (before main)\n")));
    let p = temp_script("err3.lua", "function main()\n  m.log()\nend\n");
    let mut l = Lua::new();
    l.load(&p).unwrap();
    assert!(!l.run(&mut t, b""));
    assert!(log.text().contains(&format!(
        "[2] Failed to execute lua script: {p} (main) - {p}:2: bad argument #1 to 'log' (number expected, got no value)\n"
    )));
    // `modsec` is the "luaL_msc" metatable.
    let p = temp_script("modsec.lua", "function main()\n  return getmetatable == nil and '' or modsec.__name\nend\n");
    let mut l = Lua::new();
    l.load(&p).unwrap();
    assert!(l.run(&mut t, b""));
    assert!(log.text().contains("Returning from lua script: luaL_msc\n"));
}

#[test]
fn setvar_and_getvar() {
    let ms = ModSecurity::new();
    let (mut rules, log) = rules_with_log();
    rules.properties.settings.sec_web_app_id = Some("app".to_string());
    let mut t = Transaction::new(&ms, &rules, None);
    // The persistent collections may live on disk (LMDB).
    let ip_key = format!("lua-test-{}", std::process::id());
    t.collections.ip.key = ip_key.as_bytes().to_vec();

    assert!(!loaded("setvar.lua").run(&mut t, b""));
    assert_eq!(t.collections.tx.get(b"lua_set_var"), Some(&b"2"[..]));
    assert_eq!(
        ms.ip_collection.resolve_first(format!("{}::app::lua_set_var", ip_key).as_bytes()),
        Ok(Some(b"2".to_vec()))
    );

    assert!(loaded("match-set.lua").run(&mut t, b""));
    assert_eq!(t.collections.tx.get(b"test"), Some(&b"whee"[..]));

    t.collections.tx.set(b"test", b"FELIPE".to_vec());
    assert!(loaded("match-getvar-transformation.lua").run(&mut t, b""));
    assert!(log.text().contains("Just fine."));
    assert!(loaded("match-getvar-multi-transformations.lua").run(&mut t, b""));
    assert!(log.text().contains("Whee. Working like a charm. That is what we have: FELIPE"));

    t.collections.tx.set(b"test", b"2".to_vec());
    assert!(loaded("match-getvar.lua").run(&mut t, b""));
    assert!(log.text().contains("Number is bigger than one."));

    // Unknown variables.
    assert!(!loaded("lua-getvar-unknown.lua").run(&mut t, b""));
    assert!(log.text().contains("[2] Lua: m.getvar(): unknown variable: UNKNOWN_VARIABLE.\n"));
    assert!(log.text().contains("UNKNOWN_VARIABLE is not available from Lua."));
    assert!(!loaded("lua-getvars-rule.lua").run(&mut t, b""));
    assert!(log.text().contains("[2] Lua: m.getvars(): unknown variable: RULE.\n"));
    assert!(log.text().contains("RULE from Lua: 0 value(s)."));

    // setvar argument checks.
    let p = temp_script("setvar-args.lua", "function main()\n  m.setvar('x')\n  m.setvar('novalue', 'v')\nend\n");
    let mut l = Lua::new();
    l.load(&p).unwrap();
    assert!(!l.run(&mut t, b""));
    assert!(log.text().contains("[8] m.setvar: Failed m.setvar function must have 2 arguments\n"));
    assert!(
        log.text()
            .contains("[8] m.setvar: Must specify a collection using dot character - ie m.setvar(tx.myvar,mydata)\n")
    );

    // Bad transformation parameter type.
    let p = temp_script("tfn.lua", "function main()\n  m.getvar('tx.test', true)\nend\n");
    let mut l = Lua::new();
    l.load(&p).unwrap();
    l.run(&mut t, b"");
    assert!(log.text().contains(
        "[8] SecRuleScript: Transformation parameter must be a transformation name or array of transformation names, but found userdata (type 1)\n"
    ));
}

/// The expected lines are the debug log of libmodsecurity 3.0.17 for
/// the same script, but for the spelling of the m.setvar message.
#[test]
fn callback_errors_match_cpp() {
    let ms = ModSecurity::new();
    let (rules, log) = rules_with_log();
    let mut t = Transaction::new(&ms, &rules, None);
    let p = temp_script(
        "probe.lua",
        r#"function main()
  m.log(1, "count=" .. select('#', m.getvar('tx.nothere')) .. " modsec=" .. tostring(modsec.__name))
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
    let got = log.text().clone();
    assert!(ret, "{}", got);
    let expected = format!(
        "[1] count=0 modsec=luaL_msc
[8] m.setvar: Failed m.setvar function must have 2 arguments
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
    assert!(!loaded("match-getvars-args.lua").run(&mut t, b""));
    assert!(log.text().contains("ARGS count read =2"));
    assert!(!loaded("match-getvars.lua").run(&mut t, b""));
    let s = log.text().clone();
    assert!(s.contains("[\"name\"] = QUERY_STRING,") && s.contains("[\"value\"] = a=1&b=2,"), "{}", s);
}
