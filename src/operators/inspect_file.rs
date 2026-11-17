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
    file: String,
    is_script: bool,
    lua: Lua,
}

impl InspectFile {
    pub fn new(param: Param) -> Self {
        InspectFile { param, file: String::new(), is_script: false, lua: Lua::new() }
    }

    /// Runs `self.file` with `arg` (posix_spawn of the C++ code: the path is
    /// not searched in `PATH`, the environment, stdin and stderr are
    /// inherited and stdout is captured). Returns the captured output when
    /// the program exited with status 0.
    #[cfg(unix)]
    fn run_program(&self, arg: &[u8]) -> Option<Vec<u8>> {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};

        // posix_spawn takes the path as is; std::process would search PATH
        // for a bare name, so make such a path explicitly relative.
        let program = if self.file.contains('/') { self.file.clone() } else { format!("./{}", self.file) };
        // The argument is passed as a C string.
        let end = arg.iter().position(|&c| c == 0).unwrap_or(arg.len());

        let output = Command::new(program)
            .arg0(&self.file)
            .arg(OsStr::from_bytes(&arg[..end]))
            .stdin(Stdio::inherit())
            .stderr(Stdio::inherit())
            .stdout(Stdio::piped())
            .output()
            .ok()?;

        // WIFEXITED(wstatus) == 0 || WEXITSTATUS(wstatus) != 0
        if output.status.code() != Some(0) {
            return None;
        }
        Some(output.stdout)
    }

    /// Windows variant (`CreateProcessW` in C++).
    #[cfg(not(unix))]
    fn run_program(&self, arg: &[u8]) -> Option<Vec<u8>> {
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

    /// Finds the program or script; `param2` is the configuration file of
    /// the rule.
    pub fn init(&mut self, param2: &str) -> Result<(), String> {
        let param = self.param.literal_lossy();

        let lookup = find_resource(&param, param2);
        self.file = lookup.path.unwrap_or_default();
        if std::fs::File::open(&self.file).is_err() {
            return Err(format!("Failed to open file: {}. {}", param, lookup.looked_at));
        }

        if let Ok(lua) = Lua::from_script(&self.file) {
            self.lua = lua;
            self.is_script = true;
        }

        Ok(())
    }

    /// Whether the script or program reports a match for `input` (a file
    /// name).
    pub fn evaluate(&self, t: &mut Transaction<'_>, input: &[u8]) -> bool {
        if self.is_script {
            // Lua scripts need a transaction to run against.
            return self.lua.run(t, input);
        }

        let Some(res) = self.run_program(input) else {
            return false;
        };
        if res.len() > 1 && res[0] != b'1' {
            return true; // match
        }

        // no match
        false
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::operators::operator::Operator;
    use crate::operators::operator::test_support::eval;

    /// The operator with its program set (init() also asks the Lua engine
    /// whether the file is a script).
    fn op(file: &str) -> Operator {
        let mut o = InspectFile::new(Param::from_text(file));
        o.file = file.to_string();
        Operator::InspectFile(o)
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

    #[test]
    fn missing_file() {
        let mut o = InspectFile::new(Param::from_text("/nonexistent/prog"));
        let e = o.init("/etc/x.conf").unwrap_err();
        assert!(e.starts_with("Failed to open file: /nonexistent/prog. Looking at: "), "{}", e);
    }
}
