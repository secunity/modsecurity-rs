//! The engine instance ([`ModSecurity`]): its collections, server log
//! callback and connector information, and the version constants.

use std::any::Any;
use std::ffi::{CStr, CString};
use std::sync::OnceLock;

use crate::collection::Collection;
use crate::rule::message::{LogParts, RuleMessage};
use crate::transaction::Transaction;

pub const MODSECURITY_MAJOR: &str = "3";
pub const MODSECURITY_MINOR: &str = "0";
pub const MODSECURITY_PATCHLEVEL: &str = "17";
pub const MODSECURITY_TAG_NUM: &str = "100";
pub const MODSECURITY_VERSION: &str = "3.0.17";
#[cfg_attr(not(feature = "curl"), allow(dead_code))] // Sent by the HTTPS client.
pub const MODSECURITY_VERSION_NUM: u64 = 30170100;

bitflags::bitflags! {
    /// What the server log callback receives
    /// ([`ModSecurity::set_server_log_cb_with_properties`]). The bits are
    /// those of the C++ `LogProperty` enumeration.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct LogProperties: u8 {
        /// The text of the log entry.
        const TEXT = 1;
        /// The rule message itself, instead of the text.
        const RULE_MESSAGE = 2;
        /// The highlight information of the rule message (no effect, as
        /// in C++).
        const INCLUDE_FULL_HIGHLIGHT = 4;
    }
}

/// What the server log callback receives (C++ passes either a `const char*`
/// or a `RuleMessage*` through a `const void*`, depending on the log
/// properties).
pub enum ServerLogEntry<'m, 't> {
    Text(&'m str),
    RuleMessage(&'m RuleMessage<'m>, &'m Transaction<'t>),
}

/// The server log callback: called with the transaction's callback data
/// (the C++ `void *` given to the `Transaction` constructor) and the log
/// entry.
pub type ModSecLogCb = Box<dyn Fn(Option<&(dyn Any + Send)>, ServerLogEntry<'_, '_>) + Send + Sync>;

/// The engine instance: persistent collections, connector information and
/// the server log callback. Shared (read-only) by all transactions.
pub struct ModSecurity {
    pub(crate) global_collection: Box<dyn Collection>,
    pub(crate) resource_collection: Box<dyn Collection>,
    pub(crate) ip_collection: Box<dyn Collection>,
    pub(crate) session_collection: Box<dyn Collection>,
    pub(crate) user_collection: Box<dyn Collection>,
    connector: String,
    /// NUL terminated for `msc_who_am_i`.
    whoami: OnceLock<CString>,
    log_cb: Option<ModSecLogCb>,
    log_properties: LogProperties,
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
        // `audit_log::writer::generate_boundary`.)
        // (A no-op without libxml2.)
        modsecurity_body::xml::init_parser();
        ModSecurity {
            global_collection: new_collection("GLOBAL"),
            resource_collection: new_collection("RESOURCE"),
            ip_collection: new_collection("IP"),
            session_collection: new_collection("SESSION"),
            user_collection: new_collection("USER"),
            connector: String::new(),
            whoami: OnceLock::new(),
            log_cb: None,
            log_properties: LogProperties::empty(),
        }
    }

    /// The library version and platform, e.g.
    /// `ModSecurity v3.0.17 (Linux)`.
    pub fn who_am_i(&self) -> &str {
        // ASCII: the conversion cannot fail.
        self.who_am_i_c().to_str().unwrap_or_default()
    }

    /// [`who_am_i`](Self::who_am_i) as a C string (`msc_who_am_i`), which
    /// lives as long as the instance.
    pub fn who_am_i_c(&self) -> &CStr {
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
            CString::new(format!("ModSecurity v{} ({})", MODSECURITY_VERSION, platform)).unwrap_or_default()
        })
    }

    pub fn set_connector_information(&mut self, connector: &str) {
        self.connector = connector.to_string();
    }

    pub fn connector_information(&self) -> &str {
        &self.connector
    }

    /// Sets the server log callback; it receives text log entries.
    pub fn set_server_log_cb(&mut self, cb: ModSecLogCb) {
        self.set_server_log_cb_with_properties(cb, LogProperties::TEXT);
    }

    /// Sets the server log callback and what it receives: with
    /// [`LogProperties::TEXT`] the text of each entry, otherwise with
    /// [`LogProperties::RULE_MESSAGE`] the rule message.
    pub fn set_server_log_cb_with_properties(&mut self, cb: ModSecLogCb, properties: LogProperties) {
        self.log_cb = Some(cb);
        self.log_properties = properties;
    }

    /// Sends a rule message to the server log callback, as text or as the
    /// message itself depending on the log properties (to stderr when no
    /// callback is set).
    pub(crate) fn server_log(&self, data: Option<&(dyn Any + Send)>, rm: &RuleMessage<'_>, t: &Transaction<'_>) {
        let Some(cb) = &self.log_cb else {
            eprintln!("Server log callback is not set -- {}", rm.error_log(t));
            return;
        };
        if self.log_properties.contains(LogProperties::TEXT) {
            let d = rm.log(t, LogParts::empty(), None);
            cb(data, ServerLogEntry::Text(&d));
            return;
        }
        if self.log_properties.contains(LogProperties::RULE_MESSAGE) {
            cb(data, ServerLogEntry::RuleMessage(rm, t));
        }
    }

    /// Renders the highlight information of a `RuleMessage` reference as
    /// JSON.
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
        use crate::actions::transformation::Transformation;
        use modsecurity_compat::json::JsonGen;
        use modsecurity_native::regex::Regex;

        // The regex captures contain decimal digits, so general C++ prefix
        // parsing (whitespace, signs, trailing text) is unnecessary here.
        // Keep its signed 32-bit range and externally reported error text.
        fn parse_offset(bytes: &[u8]) -> Result<usize, &'static str> {
            std::str::from_utf8(bytes)
                .map_err(|_| "stoi")?
                .parse::<i32>()
                .map(|offset| offset as usize)
                .map_err(|_| "stoi")
        }

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
        let content = modsecurity_compat::chars::c_str(content);
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

            let start = parse_offset(starting_at)?;
            if start >= len {
                return Err("Offset is out of the content limits.".to_string());
            }

            let end = start.saturating_add(parse_offset(size)?).min(len);
            let value = &content[start..end];
            if !var_value.is_empty() {
                var_value.push(b' ');
            }
            var_value.extend_from_slice(value);
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

            let start = parse_offset(starting_at)?;
            if start >= var_value.len() {
                return Err("Offset is out of the variable limits.".to_string());
            }
            g.string(b"value");

            let end = start.saturating_add(parse_offset(size)?).min(var_value.len());
            g.string(&var_value[start..end]);
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

    #[test]
    fn numeric_boundaries_and_error_precedence() {
        for (offsets, error) in [
            ("v2147483647,1v0,1", "Offset is out of the content limits."),
            ("v2147483648,1v0,1", "stoi"),
            ("v0,2147483648v0,1", "stoi"),
            // The starting offset is checked before parsing the size.
            ("v5,2147483648v0,1", "Offset is out of the content limits."),
        ] {
            assert_eq!(pco("Hello", offsets).unwrap_err(), error, "{offsets}");
        }
        assert!(pco("Hello", "v0001,2147483647v0,1").unwrap().contains("\"value\":\"ello\""));
        assert!(pco("Hello", "v1,0v0,1").unwrap().contains("\"value\":\"\""));
    }

    #[test]
    fn ranges_are_bytes_and_content_stops_at_nul() {
        let output = ModSecurity::process_content_offset(b"a\xffz\0ignored", "v1,99v0,1").unwrap();
        assert!(output.windows(2).any(|bytes| bytes == b"\xffz"));
        assert!(!output.windows(7).any(|bytes| bytes == b"ignored"));
        assert_eq!(pco("abc\0ignored", "v3,0v0,1").unwrap_err(), "Offset is out of the content limits.");
    }
}
