//! Port of `test/common/` (shared by the regression and unit test
//! utilities): test file loading, the custom debug log and helpers.

#![allow(dead_code)]

use std::sync::Mutex;

use modsecurity::debug_log::debug_log::DebugLog;
use modsecurity::utils::json::{JsonValue, parse_tree};

pub const RESET: &str = "\x1B[0m";
pub const KRED: &str = "\x1B[31m";
pub const KGRN: &str = "\x1B[32m";
pub const KCYN: &str = "\x1B[36m";
pub const KWHT: &str = "\x1B[37m";

/// The optional features this build has, named like the `resource` field of
/// the test cases.
pub fn resources() -> Vec<&'static str> {
    let mut r = Vec::new();
    if cfg!(feature = "maxmind") {
        r.push("geoip-or-maxmind");
        r.push("maxmind");
    }
    if cfg!(feature = "curl") {
        r.push("curl");
    }
    if cfg!(feature = "ssdeep") {
        r.push("ssdeep");
    }
    if cfg!(feature = "lua") {
        r.push("lua");
    }
    if cfg!(feature = "libxml2") {
        r.push("libxml2");
    }
    if cfg!(feature = "regex-dollar-endonly") {
        r.push("regex-dollar-endonly");
    }
    r
}

/// Loads every `*.json` file of `path` (or `path` itself if it is a file).
/// Each file holds an array of test objects.
pub fn load_tests(path: &str) -> Vec<(String, Vec<JsonValue>)> {
    let mut files = Vec::new();
    match std::fs::read_dir(path) {
        Ok(rd) => {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                if name.ends_with(".json") {
                    files.push(format!("{}/{}", path, name));
                }
            }
        }
        Err(_) => {
            if std::path::Path::new(path).is_file() {
                files.push(path.to_string());
            }
        }
    }
    let mut out = Vec::new();
    for f in files {
        let Ok(data) = std::fs::read(&f) else {
            println!("Problems loading from: {}", f);
            continue;
        };
        match parse_tree(&data) {
            Ok(JsonValue::Array(a)) => out.push((f, a)),
            Ok(v @ JsonValue::Object(_)) => out.push((f, vec![v])),
            _ => println!("Problems loading tests from: {}", f),
        }
    }
    out
}

/// `YAJL_GET_STRING`: the C string of a JSON string (truncated at NUL).
pub fn json_string(v: Option<&JsonValue>) -> Vec<u8> {
    match v {
        Some(JsonValue::String(s)) => match s.iter().position(|&c| c == 0) {
            Some(p) => s[..p].to_vec(),
            None => s.clone(),
        },
        _ => Vec::new(),
    }
}

pub fn json_int(v: Option<&JsonValue>) -> i64 {
    v.and_then(|v| v.as_i64()).unwrap_or(0)
}

/// `json2bin`: replaces `\xHH` and `\uHHHH` escapes (written literally in
/// the JSON strings) with the corresponding byte.
pub fn json2bin(s: &mut Vec<u8>) {
    fn hexval(d: &[u8]) -> Option<u32> {
        u32::from_str_radix(std::str::from_utf8(d).ok()?, 16).ok()
    }
    // C++ loops "while regex_search(...)" replacing all occurrences of the
    // first match each time; process \x first, then \u.
    for (prefix, len) in [(b'x', 2usize), (b'u', 4usize)] {
        loop {
            let mut found = None;
            let mut i = 0;
            while i + 2 + len <= s.len() {
                if s[i] == b'\\'
                    && s[i + 1] == prefix
                    && s[i + 2..i + 2 + len].iter().all(|c| c.is_ascii_alphanumeric())
                {
                    found = Some(s[i..i + 2 + len].to_vec());
                    break;
                }
                i += 1;
            }
            let Some(m) = found else {
                break;
            };
            // sscanf("%3x"/"%4x"): the leading hex digits of the group (C++
            // leaves the value uninitialised when there are none; 0 here).
            let digits: Vec<u8> = m[2..].iter().copied().take_while(u8::is_ascii_hexdigit).collect();
            let p = hexval(&digits).unwrap_or(0) as u8;
            let mut out = Vec::with_capacity(s.len());
            let mut j = 0;
            while j < s.len() {
                if s[j..].starts_with(&m) {
                    out.push(p);
                    j += m.len();
                } else {
                    out.push(s[j]);
                    j += 1;
                }
            }
            *s = out;
        }
    }
}

/// `CustomDebugLog`: keeps every line in memory so tests can match it.
#[derive(Default)]
pub struct CustomDebugLog {
    log: Mutex<String>,
    level: i32,
}

impl CustomDebugLog {
    pub fn new() -> Self {
        CustomDebugLog { log: Mutex::new(String::new()), level: -1 }
    }

    pub fn log_messages(&self) -> String {
        self.log.lock().unwrap().clone()
    }

    /// `contains(pattern)`: regex search over the whole log.
    pub fn contains(&self, pattern: &str) -> bool {
        let re = modsecurity::utils::regex::Regex::new(pattern);
        let s = self.log.lock().unwrap();
        re.search(s.as_bytes()) > 0
    }
}

impl DebugLog for CustomDebugLog {
    fn write(&self, level: i32, msg: &str) {
        let mut l = self.log.lock().unwrap();
        l.push_str(&format!("[{}] {}\n", level, msg));
    }

    fn write_ctx(&self, level: i32, id: &str, uri: &str, msg: &str) {
        let mut l = self.log.lock().unwrap();
        l.push_str(&format!("[{}] [{}] [{}] {}\n", id, uri, level, msg));
    }

    fn is_log_file_set(&self) -> bool {
        false
    }

    fn is_log_level_set(&self) -> bool {
        self.level != -1
    }

    fn set_debug_log_level(&mut self, level: i32) {
        self.level = level;
    }

    fn set_debug_log_file(&mut self, _file_name: &str, _error: &mut String) {}

    fn get_debug_log_file(&self) -> &str {
        ""
    }

    /// The C++ `CustomDebugLog::getDebugLogLevel` always reports 9.
    fn get_debug_log_level(&self) -> i32 {
        9
    }

    fn debug_level(&self) -> i32 {
        self.level
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

pub fn lossy(s: &[u8]) -> String {
    String::from_utf8_lossy(s).into_owned()
}
