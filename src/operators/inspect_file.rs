//! The `@inspectFile` operator: checks the value with a script or an
//! external program.
//!
//! The parameter is either a Lua script (run through `lua::Lua`) or
//! an external program that receives the value as its only argument; the
//! program "matches" when it exits successfully and its output does not
//! start with `1` (and is longer than one byte).

use crate::lua::Lua;
use crate::operators::operator::Param;
use crate::transaction::Transaction;
use crate::utils::system::find_resource;

#[derive(Debug)]
pub struct InspectFile {
    param: Param,
    /// The program or script.
    file: String,
    /// The script, when `file` is a Lua script.
    script: Option<Lua>,
}

impl InspectFile {
    /// Finds the program or script `param` names; `param2` is the
    /// configuration file of the rule.
    pub fn new(param: Param, param2: &str) -> Result<Self, String> {
        let name = param.literal_lossy();

        let lookup = find_resource(&name, param2);
        let file = lookup.path.unwrap_or_default();
        if std::fs::File::open(&file).is_err() {
            return Err(format!("Failed to open file: {}. {}", name, lookup.looked_at));
        }

        // A `.lua` file is a script: one that does not load (it does not
        // compile, or Lua support is not built in) is an error, not a
        // program to run.
        let script = if file.ends_with(".lua") { Some(Lua::from_script(&file)?) } else { None };
        Ok(InspectFile { param, file, script })
    }

    /// Runs `self.file` with `arg`, as `posix_spawn` would: the path is
    /// not searched in `PATH`, stdin and stderr are inherited and stdout
    /// is captured. The program gets the environment of the process plus
    /// `envs`, what `setenv` actions set in the transaction. Returns the
    /// captured output when the program exited with status 0.
    #[cfg(unix)]
    fn run_program(&self, arg: &[u8], envs: &std::collections::BTreeMap<Vec<u8>, Vec<u8>>) -> Option<Vec<u8>> {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};

        // The path is used as it is; `std::process` would search PATH
        // for a bare name, so make such a path explicitly relative.
        let program = if self.file.contains('/') { self.file.clone() } else { format!("./{}", self.file) };
        // The argument is passed as a C string.
        let arg = modsecurity_compat::chars::c_str(arg);

        // What the system cannot take as an environment entry is left out.
        let passable = |(name, value): &(&Vec<u8>, &Vec<u8>)| {
            !name.is_empty() && !name.contains(&b'=') && !name.contains(&0) && !value.contains(&0)
        };
        let envs = envs.iter().filter(passable).map(|(n, v)| (OsStr::from_bytes(n), OsStr::from_bytes(v)));

        let output = Command::new(program)
            .arg0(&self.file)
            .arg(OsStr::from_bytes(arg))
            .envs(envs)
            .stdin(Stdio::inherit())
            .stderr(Stdio::inherit())
            .stdout(Stdio::piped())
            .output()
            .ok()?;

        // A program killed by a signal, or that exits with another status,
        // does not match.
        if output.status.code() != Some(0) {
            return None;
        }
        Some(output.stdout)
    }

    /// The variant for the other platforms: stdout is captured, and the
    /// output is returned when the program exited with status 0.
    #[cfg(not(unix))]
    fn run_program(&self, arg: &[u8], _envs: &std::collections::BTreeMap<Vec<u8>, Vec<u8>>) -> Option<Vec<u8>> {
        use std::process::{Command, Stdio};
        let arg = String::from_utf8(arg.to_vec()).ok()?;
        let output = Command::new(&self.file).arg(arg).stdout(Stdio::piped()).output().ok()?;
        if output.status.code() != Some(0) {
            return None;
        }
        Some(output.stdout)
    }
}

impl InspectFile {
    pub fn param(&self) -> &Param {
        &self.param
    }

    /// Whether the script or program reports a match for `input` (a file
    /// name).
    pub fn evaluate(&self, t: &mut Transaction<'_>, input: &[u8]) -> bool {
        if let Some(lua) = &self.script {
            // Lua scripts need a transaction to run against.
            return lua.run(t, input);
        }

        let Some(res) = self.run_program(input, &t.variable_envs) else {
            return false;
        };
        if res.len() > 1 && res[0] != b'1' {
            return true;
        }
        false
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::operators::operator::Operator;
    use crate::operators::operator::test_support::eval;

    /// The operator of the program `file`, without asking the Lua engine
    /// whether the file is a script.
    fn op(file: &str) -> Operator {
        Operator::InspectFile(InspectFile { param: Param::from_text(file), file: file.to_string(), script: None })
    }

    #[test]
    fn external_program() {
        // /bin/echo prints its argument: "1\n" does not match, "0\n" does.
        let echo = op("/bin/echo");
        assert!(!eval(&echo, b"1"));
        assert!(eval(&echo, b"0"));
        assert!(eval(&echo, b"whee"));

        let helper = format!("{}/test/test-cases/data/inspectfile-posix-helper.sh", env!("CARGO_MANIFEST_DIR"));
        let helper = op(&helper);
        assert!(eval(&helper, b"match"));
        assert!(!eval(&helper, b"nomatch"));
        // Output on stderr only, and a non-zero exit status, never match.
        assert!(!eval(&helper, b"stderr-only"));
        assert!(!eval(&helper, b"other"));
        // Spaces and shell characters are passed as a single argument.
        assert!(!eval(&helper, b"match; echo 0"));

        let not_exec = format!("{}/test/test-cases/data/inspectfile-not-executable.txt", env!("CARGO_MANIFEST_DIR"));
        assert!(!eval(&op(&not_exec), b"match"));
    }

    /// A `.lua` file that does not load refuses the rule. (It used to be
    /// run as a program.)
    #[test]
    fn a_lua_script_that_does_not_load_is_an_error() {
        let dir = std::env::temp_dir().join(format!("msrs-inspectfile-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("broken.lua");
        std::fs::write(&script, "function main( return 1 end\n").unwrap();
        let e = InspectFile::new(Param::from_text(script.to_str().unwrap()), "/etc/x.conf").unwrap_err();
        if cfg!(feature = "lua") {
            assert!(e.starts_with("Problems load script: Failed to compile script '"), "{}", e);
        } else {
            assert_eq!(e, "Lua support was not enabled.");
        }
        let mut rules = crate::RulesSet::new();
        let conf = format!("SecRule FILES_TMPNAMES \"@inspectFile {}\" \"id:1,phase:2,deny\"", script.display());
        assert!(rules.load(&conf).unwrap_err().message().contains(&e));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn missing_file() {
        let e = InspectFile::new(Param::from_text("/nonexistent/prog"), "/etc/x.conf").unwrap_err();
        assert!(e.starts_with("Failed to open file: /nonexistent/prog. Looking at: "), "{}", e);
    }
}
