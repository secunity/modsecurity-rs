//! Port of `headers/modsecurity/modsecurity.h` and `src/modsecurity.cc`.

use std::any::Any;
use std::sync::OnceLock;

use crate::collection::collection::Collection;
use crate::rule_message::RuleMessage;
use crate::transaction::Transaction;

/// The Phases enumerator consists in mapping the different stages of a given
/// request. ModSecurity is expected to inspect data based on those "phases".
/// It is mandatory to call all the phases, even if you don't have this
/// phases segmented in your end.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(i32)]
pub enum Phases {
    /// The very first information that ModSecurity can inspect, right
    /// after a connection is established.
    ConnectionPhase = 0,
    /// Happens just after the server has the full request URI.
    UriPhase = 1,
    /// The server has all the request headers (before the body).
    RequestHeadersPhase = 2,
    /// Request body inspection.
    RequestBodyPhase = 3,
    /// Just before the response headers are delivered.
    ResponseHeadersPhase = 4,
    /// Response body inspection.
    ResponseBodyPhase = 5,
    /// Logging; no disruptive action can happen here.
    LoggingPhase = 6,
}

/// Just a marking for the expected number of phases.
pub const NUMBER_OF_PHASES: usize = 7;

pub const MODSECURITY_MAJOR: &str = "3";
pub const MODSECURITY_MINOR: &str = "0";
pub const MODSECURITY_PATCHLEVEL: &str = "17";
pub const MODSECURITY_TAG: &str = "";
pub const MODSECURITY_TAG_NUM: &str = "100";
pub const MODSECURITY_VERSION: &str = "3.0.17";
pub const MODSECURITY_VERSION_NUM: u64 = 30170100;

/// `MODSECURITY_CHECK_VERSION(a)`
pub const fn modsecurity_check_version(a: u64) -> bool {
    MODSECURITY_VERSION_NUM <= a
}

/// Original ModSecurity text log entry.
pub const TEXT_LOG_PROPERTY: i32 = 1;
/// Pass the RuleMessage instead of the text entry.
pub const RULE_MESSAGE_LOG_PROPERTY: i32 = 2;
/// Fill the highlight information of the RuleMessage.
pub const INCLUDE_FULL_HIGHLIGHT_LOG_PROPERTY: i32 = 4;

/// What the server log callback receives (C++ passes either a `const char*`
/// or a `RuleMessage*` through a `const void*`, depending on the log
/// properties).
pub enum ServerLogEntry<'m, 't> {
    Text(&'m str),
    RuleMessage(&'m RuleMessage<'m>, &'m Transaction<'t>),
}

/// `ModSecLogCb`: called with the transaction's callback data (the C++
/// `void *` given to the `Transaction` constructor) and the log entry.
pub type ModSecLogCb = Box<dyn Fn(Option<&(dyn Any + Send)>, ServerLogEntry<'_, '_>) + Send + Sync>;

/// The engine instance: persistent collections, connector information and
/// the server log callback. Shared (read-only) by all transactions.
pub struct ModSecurity {
    pub global_collection: Box<dyn Collection>,
    pub resource_collection: Box<dyn Collection>,
    pub ip_collection: Box<dyn Collection>,
    pub session_collection: Box<dyn Collection>,
    pub user_collection: Box<dyn Collection>,
    connector: String,
    whoami: OnceLock<String>,
    log_cb: Option<ModSecLogCb>,
    log_properties: i32,
}

impl Default for ModSecurity {
    fn default() -> Self {
        Self::new()
    }
}

fn new_collection(name: &str) -> Box<dyn Collection> {
    #[cfg(feature = "lmdb")]
    {
        Box::new(crate::collection::backend::lmdb::Lmdb::new(name))
    }
    #[cfg(not(feature = "lmdb"))]
    {
        Box::new(crate::collection::backend::in_memory_per_process::InMemoryPerProcess::new(name))
    }
}

impl ModSecurity {
    pub fn new() -> Self {
        crate::unique_id::UniqueId::unique_id();
        // (C++ calls `srand(time(NULL))` here to seed libc `rand()` for the
        // audit log boundaries; those now come from the `rand` crate, see
        // `audit_log::writer::writer::generate_boundary`.)
        // (A no-op without libxml2.)
        crate::request_body_processor::xml::init_parser();
        ModSecurity {
            global_collection: new_collection("GLOBAL"),
            resource_collection: new_collection("RESOURCE"),
            ip_collection: new_collection("IP"),
            session_collection: new_collection("SESSION"),
            user_collection: new_collection("USER"),
            connector: String::new(),
            whoami: OnceLock::new(),
            log_cb: None,
            log_properties: 0,
        }
    }

    /// `whoAmI`: e.g. `ModSecurity v3.0.17 (Linux)`.
    pub fn who_am_i(&self) -> &str {
        self.whoami.get_or_init(|| {
            let platform = if cfg!(target_os = "aix") {
                "AIX"
            } else if cfg!(target_os = "linux") {
                "Linux"
            } else if cfg!(target_os = "openbsd") {
                "OpenBSD"
            } else if cfg!(target_os = "solaris") {
                "Solaris"
            } else if cfg!(target_os = "macos") {
                "MacOSX"
            } else if cfg!(target_os = "freebsd") {
                "FreeBSD"
            } else if cfg!(target_os = "dragonfly") {
                "DragonFlyBSD"
            } else if cfg!(target_os = "netbsd") {
                "NetBSD"
            } else if cfg!(target_os = "windows") {
                "Windows"
            } else {
                "Unknown platform"
            };
            format!("ModSecurity v{} ({})", MODSECURITY_VERSION, platform)
        })
    }

    pub fn set_connector_information(&mut self, connector: &str) {
        self.connector = connector.to_string();
    }

    pub fn get_connector_information(&self) -> &str {
        &self.connector
    }

    /// `setServerLogCb(cb)` (text log entries).
    pub fn set_server_log_cb(&mut self, cb: ModSecLogCb) {
        self.set_server_log_cb_with_properties(cb, TEXT_LOG_PROPERTY);
    }

    /// `setServerLogCb(cb, properties)`
    pub fn set_server_log_cb_with_properties(&mut self, cb: ModSecLogCb, properties: i32) {
        self.log_cb = Some(cb);
        self.log_properties = properties;
    }

    /// `serverLog(data, rm)`
    pub fn server_log(&self, data: Option<&(dyn Any + Send)>, rm: &RuleMessage<'_>, t: &Transaction<'_>) {
        let Some(cb) = &self.log_cb else {
            eprintln!("Server log callback is not set -- {}", rm.error_log(t));
            return;
        };
        if self.log_properties & TEXT_LOG_PROPERTY != 0 {
            let d = rm.log(t, 0, -1);
            cb(data, ServerLogEntry::Text(&d));
            return;
        }
        if self.log_properties & RULE_MESSAGE_LOG_PROPERTY != 0 {
            cb(data, ServerLogEntry::RuleMessage(rm, t));
        }
    }

    /// `processContentOffset`: renders the highlight information of a
    /// `RuleMessage` reference as JSON.
    ///
    /// `match_string` holds the offsets as written in the logs, e.g.
    /// `o0,4v64,13v114,4t:lowercase` (`v<start>,<size>` variable offsets
    /// in `content`, `o<start>,<size>` operator offsets in the variable
    /// value, `t:<name>` transformations). The C++ `err` out-parameter is
    /// the `Err` value; where the C++ code throws a standard exception
    /// (`std::stoi`, `std::string` constructor), the `Err` carries the
    /// exception's `what()` text.
    ///
    /// The C++ quirks are kept: the last `v`/`o` entry is never used
    /// (`pending > 3`), the operator size is taken from the first operator
    /// entry as a whole (`ops.back()`, e.g. `o0,4`, which then makes
    /// `std::stoi` throw), and the closing brackets do not match the
    /// opened containers (yajl does not check them and rejects the last
    /// one).
    pub fn process_content_offset(content: &[u8], match_string: &str) -> Result<Vec<u8>, String> {
        use crate::actions::transformations::transformation::Transformation;
        use crate::utils::json::JsonGen;
        use crate::utils::regex::Regex;

        let variables = Regex::new("v([0-9]+),([0-9]+)");
        let operators = Regex::new("o([0-9]+),([0-9]+)");
        let transformations = Regex::new("t:(?:(?!t:).)+");
        let mut var_value: Vec<u8> = Vec::new();

        // `searchAll` builds its list with push_front: `rbegin()` walks the
        // matches in order, three entries each (whole match, start, size),
        // and `back()` is the first entry.
        let vars = variables.search_all(match_string.as_bytes());
        let ops = operators.search_all(match_string.as_bytes());
        let mut trans = transformations.search_all(match_string.as_bytes());

        // `content` is read as a C string.
        let content = &content[..content.iter().position(|&c| c == 0).unwrap_or(content.len())];
        let len = content.len();

        let mut g = JsonGen::new();

        g.map_open();
        g.string(b"match");

        g.array_open();
        g.map_open();

        g.string(b"variable");

        g.map_open();
        g.string(b"highlight");

        g.array_open();
        let mut it = vars.iter().rev();
        let mut pending = vars.len();
        while pending > 3 {
            g.map_open();
            it.next();
            let starting_at = it.next().map(|m| m.str()).unwrap_or_default();
            let size = it.next().map(|m| m.str()).unwrap_or_default();
            g.string(b"startingAt");
            g.string(starting_at);
            g.string(b"size");
            g.string(size);
            g.map_close();

            let start = Self::stoi(starting_at)?;
            if start as usize >= len {
                return Err("Offset is out of the content limits.".to_string());
            }

            let value = Self::substr(content, start as usize, Self::stoi(size)? as usize)?;
            if !var_value.is_empty() {
                var_value.push(b' ');
            }
            var_value.extend_from_slice(&value);
            pending -= 3;
        }
        g.array_close();

        g.string(b"value");

        g.array_open();

        g.map_open();
        g.string(b"value");
        g.string(&var_value);
        g.map_close();

        while let Some(m) = trans.pop() {
            g.map_open();
            g.string(b"transformation");

            g.string(m.str());

            let t = Transformation::from_name(&String::from_utf8_lossy(m.str()));
            t.transform(&mut var_value, None);

            g.string(b"value");
            g.string(&var_value);
            g.map_close();
        }

        g.array_close();

        g.string(b"operator");

        g.map_open();

        let mut it = ops.iter().rev();
        let mut pending = ops.len();
        while pending > 3 {
            g.string(b"highlight");
            g.map_open();
            it.next();
            let starting_at = it.next().map(|m| m.str()).unwrap_or_default();
            // Quirk (C++): `ops.back()`, not the size entry.
            let size = ops.last().map(|m| m.str()).unwrap_or_default();
            it.next();
            g.string(b"startingAt");
            g.string(starting_at);
            g.string(b"size");
            g.string(size);
            g.map_close();

            let start = Self::stoi(starting_at)?;
            if start as usize >= var_value.len() {
                return Err("Offset is out of the variable limits.".to_string());
            }
            g.string(b"value");

            let value = Self::substr(&var_value, start as usize, Self::stoi(size)? as usize)?;

            g.string(&value);
            pending -= 3;
        }

        g.map_close();

        g.map_close();
        // Quirk (C++): these close the element map, the "match" array and
        // the root map with the wrong brackets; the final
        // `yajl_gen_map_close` underflows yajl's depth and writes nothing.
        g.array_close();

        g.map_close();
        g.array_close();

        let mut json = g.into_buf();
        json.push(b'\n');
        Ok(json)
    }

    /// `std::stoi`: leading white space, optional sign, decimal digits;
    /// fails (`std::invalid_argument` / `std::out_of_range`, both "stoi")
    /// without digits or outside the `int` range.
    fn stoi(s: &[u8]) -> Result<i32, String> {
        let mut i = 0;
        while i < s.len() && matches!(s[i], b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r') {
            i += 1;
        }
        let negative = i < s.len() && s[i] == b'-';
        if i < s.len() && (s[i] == b'-' || s[i] == b'+') {
            i += 1;
        }
        let digits = s[i..].iter().take_while(|c| c.is_ascii_digit()).count();
        if digits == 0 {
            return Err("stoi".to_string());
        }
        let mut v: i64 = 0;
        for &c in &s[i..i + digits] {
            v = v * 10 + i64::from(c - b'0');
            if v > i64::from(i32::MAX) + 1 {
                return Err("stoi".to_string());
            }
        }
        let v = if negative { -v } else { v };
        i32::try_from(v).map_err(|_| "stoi".to_string())
    }

    /// `std::string(str, pos, n)`: at most `n` bytes from `pos`; throws
    /// `std::out_of_range` when `pos` is past the end.
    fn substr(s: &[u8], pos: usize, n: usize) -> Result<Vec<u8>, String> {
        if pos > s.len() {
            return Err(format!(
                "basic_string::basic_string: __pos (which is {}) > this->size() (which is {})",
                pos,
                s.len()
            ));
        }
        Ok(s[pos..pos + n.min(s.len() - pos)].to_vec())
    }
}

/// The libmodsecurity C API for the engine instance.
pub mod c_api {
    use super::{ModSecurity, ServerLogEntry};
    use std::ffi::{CStr, CString, c_char, c_void};
    use std::sync::Mutex;

    /// `ModSecLogCb` of the C API.
    pub type CModSecLogCb = Option<unsafe extern "C" fn(*mut c_void, *const c_void)>;

    /// The `void *logCbData` given to `msc_new_transaction*`.
    pub struct CLogData(pub *mut c_void);
    // SAFETY: the pointer is opaque to the library and only handed back to
    // the connector's callback, as in C++.
    unsafe impl Send for CLogData {}

    #[unsafe(no_mangle)]
    pub extern "C" fn msc_init() -> *mut ModSecurity {
        Box::into_raw(Box::new(ModSecurity::new()))
    }

    /// # Safety
    /// `msc` must come from `msc_init`. The returned string lives as long as
    /// `msc`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn msc_who_am_i(msc: *mut ModSecurity) -> *const c_char {
        static CACHE: Mutex<Option<CString>> = Mutex::new(None);
        let Some(m) = (unsafe { msc.as_ref() }) else {
            return std::ptr::null();
        };
        let mut c = CACHE.lock().unwrap_or_else(|e| e.into_inner());
        let s = c.get_or_insert_with(|| CString::new(m.who_am_i()).unwrap_or_default());
        s.as_ptr()
    }

    /// # Safety
    /// `msc` must come from `msc_init`; `connector` is a C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn msc_set_connector_info(msc: *mut ModSecurity, connector: *const c_char) {
        if let (Some(m), false) = (unsafe { msc.as_mut() }, connector.is_null()) {
            let s = unsafe { CStr::from_ptr(connector) }.to_string_lossy().into_owned();
            m.set_connector_information(&s);
        }
    }

    /// # Safety
    /// `msc` must come from `msc_init`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn msc_set_log_cb(msc: *mut ModSecurity, cb: CModSecLogCb) {
        let Some(m) = (unsafe { msc.as_mut() }) else {
            return;
        };
        let Some(cb) = cb else {
            return;
        };
        m.set_server_log_cb(Box::new(move |data, entry| {
            let d = data.and_then(|d| d.downcast_ref::<CLogData>()).map(|d| d.0).unwrap_or(std::ptr::null_mut());
            if let ServerLogEntry::Text(s) = entry {
                let c = CString::new(s.replace('\0', "")).unwrap_or_default();
                // SAFETY: calling the connector's callback with its own data
                // pointer and a NUL terminated string, as libmodsecurity does.
                unsafe { cb(d, c.as_ptr() as *const c_void) };
            }
        }));
    }

    /// # Safety
    /// `msc` must come from `msc_init` and not be used afterwards.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn msc_cleanup(msc: *mut ModSecurity) {
        if !msc.is_null() {
            drop(unsafe { Box::from_raw(msc) });
        }
    }
}

#[cfg(test)]
mod process_content_offset_tests {
    use super::ModSecurity;

    fn pco(content: &str, m: &str) -> Result<String, String> {
        ModSecurity::process_content_offset(content.as_bytes(), m).map(|v| String::from_utf8(v).unwrap())
    }

    // Expected values produced by the C++ reference build.
    #[test]
    fn reference_example() {
        let request = "GET /index.html?param1=value1&param2=value1&param3=value1 HTTP/\n\
                       AuThOrIzAtIoN: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\n\
                       Host: localhost\n\
                       Content-Length: 27\n\
                       Content-Type: application/x-www-form-urlencoded\n";
        assert_eq!(
            pco(request, "o0,4v64,13v114,4v130,14v149,12t:lowercase").unwrap(),
            "{\"match\":[{\"variable\":{\"highlight\":[{\"startingAt\":\"64\",\"size\":\"13\"},\
             {\"startingAt\":\"114\",\"size\":\"4\"},{\"startingAt\":\"130\",\"size\":\"14\"}],\
             \"value\":[{\"value\":\"AuThOrIzAtIoN Host Content-Length\"},\
             {\"transformation\":\"t:lowercase\",\"value\":\"authorization host content-length\"}],\
             \"operator\":{}}]}]\n"
        );
    }

    #[test]
    fn hand_computed() {
        assert_eq!(
            pco("Hello World Foo", "v0,50v6,5v1,1t:none").unwrap(),
            "{\"match\":[{\"variable\":{\"highlight\":[{\"startingAt\":\"0\",\"size\":\"50\"},\
             {\"startingAt\":\"6\",\"size\":\"5\"}],\"value\":[{\"value\":\"Hello World Foo World\"},\
             {\"transformation\":\"t:none\",\"value\":\"Hello World Foo World\"}],\"operator\":{}}]}]\n"
        );
        assert_eq!(
            pco("Hello", "").unwrap(),
            "{\"match\":[{\"variable\":{\"highlight\":[],\"value\":[{\"value\":\"\"}],\"operator\":{}}]}]\n"
        );
        assert_eq!(
            pco("a\"b\\c", "v0,5v0,1").unwrap(),
            "{\"match\":[{\"variable\":{\"highlight\":[{\"startingAt\":\"0\",\"size\":\"5\"}],\
             \"value\":[{\"value\":\"a\\\"b\\\\c\"}],\"operator\":{}}]}]\n"
        );
    }

    #[test]
    fn errors() {
        assert_eq!(pco("Hello World Foo", "v20,5v6,5").unwrap_err(), "Offset is out of the content limits.");
        assert_eq!(
            pco("Hello World Foo", "v0,5v6,5v12,3o20,3o2,2").unwrap_err(),
            "Offset is out of the variable limits."
        );
        // The C++ code throws std::invalid_argument / std::out_of_range.
        assert_eq!(pco("Hello World Foo", "v0,5v6,5v12,3o9,3o2,2").unwrap_err(), "stoi");
        assert_eq!(pco("Hello", "v99999999999,1v1,1").unwrap_err(), "stoi");
    }
}
