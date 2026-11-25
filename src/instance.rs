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
#[cfg_attr(not(feature = "https-client"), allow(dead_code))] // Sent by the HTTPS client.
pub const MODSECURITY_VERSION_NUM: u64 = 30170100;

bitflags::bitflags! {
    /// What the server log callback receives
    /// ([`ModSecurity::set_server_log_cb_with_properties`]). The bit values
    /// are those of libmodsecurity's `LogProperty` enumeration.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct LogProperties: u8 {
        /// The text of the log entry.
        const TEXT = 1;
        /// The rule message itself, instead of the text.
        const RULE_MESSAGE = 2;
        /// The highlight information of the rule message (no effect).
        const INCLUDE_FULL_HIGHLIGHT = 4;
    }
}

/// What the server log callback receives: the text of the entry or the rule
/// message, depending on the log properties.
pub enum ServerLogEntry<'m, 't> {
    Text(&'m str),
    RuleMessage(&'m RuleMessage<'m>, &'m Transaction<'t>),
}

/// The server log callback: called with the transaction's callback data
/// (given when the transaction was created) and the log entry.
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

/// A persistent collection, in the backend the build chose: redb, else
/// LMDB, else the memory of the process.
fn new_collection(name: &str) -> Box<dyn Collection> {
    #[cfg(feature = "redb")]
    {
        Box::new(crate::collection::backend::redb::Redb::new(name))
    }
    #[cfg(all(feature = "lmdb", not(feature = "redb")))]
    {
        Box::new(crate::collection::backend::lmdb::Lmdb::new(name))
    }
    #[cfg(not(any(feature = "lmdb", feature = "redb")))]
    {
        Box::new(crate::collection::backend::in_memory_per_process::InMemoryPerProcess::new(name))
    }
}

impl ModSecurity {
    pub fn new() -> Self {
        crate::unique_id::UniqueId::unique_id();
        // (libc `rand()` is not seeded here: the audit log boundaries come
        // from the `rand` crate, see `audit_log::writer::generate_boundary`.)
        // libxml2 is set up once per process (nothing to do without it).
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
    /// message itself depending on the log properties. Without a callback
    /// there is no server log: the message is in the audit log and in
    /// [`Transaction::rule_messages`].
    pub(crate) fn server_log(&self, data: Option<&(dyn Any + Send)>, rm: &RuleMessage<'_>, t: &Transaction<'_>) {
        let Some(cb) = &self.log_cb else { return };
        if self.log_properties.contains(LogProperties::TEXT) {
            let d = rm.log(t, LogParts::empty(), None);
            cb(data, ServerLogEntry::Text(&d));
            return;
        }
        if self.log_properties.contains(LogProperties::RULE_MESSAGE) {
            cb(data, ServerLogEntry::RuleMessage(rm, t));
        }
    }
}
