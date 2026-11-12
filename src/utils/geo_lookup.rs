//! Port of `src/utils/geo_lookup.cc`, `src/utils/geo_lookup.h`.
//!
//! Process wide geolocation database used by `@geoLookup` (configured with
//! `SecGeoLookupDb`). MaxMind databases are read with the `maxminddb` crate
//! when the `maxmind` feature is enabled (C++ `WITH_MAXMIND`). The legacy
//! GeoIP library is not available, so this behaves like a C++ build without
//! `WITH_GEOIP`.

use std::sync::RwLock;

use crate::transaction::Transaction;

/// `GeoLookupVersion`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeoLookupVersion {
    NotLoaded,
    VersionMaxmind,
    VersionGeoip,
}

#[derive(Debug)]
struct GeoLookupState {
    version: GeoLookupVersion,
    #[cfg(feature = "maxmind")]
    mmdb: Option<maxminddb::Reader<Vec<u8>>>,
}

/// `GeoLookup` (singleton, see [`GeoLookup::get_instance`]).
#[derive(Debug)]
pub struct GeoLookup {
    state: RwLock<GeoLookupState>,
}

impl GeoLookup {
    /// `getInstance`
    pub fn get_instance() -> &'static GeoLookup {
        static INSTANCE: GeoLookup = GeoLookup {
            state: RwLock::new(GeoLookupState {
                version: GeoLookupVersion::NotLoaded,
                #[cfg(feature = "maxmind")]
                mmdb: None,
            }),
        };
        &INSTANCE
    }

    /// The kind of database currently loaded.
    pub fn version(&self) -> GeoLookupVersion {
        self.state.read().unwrap_or_else(|e| e.into_inner()).version
    }

    /// `cleanUp`
    pub fn clean_up(&self) {
        let mut st = self.state.write().unwrap_or_else(|e| e.into_inner());
        #[cfg(feature = "maxmind")]
        {
            st.mmdb = None;
        }
        st.version = GeoLookupVersion::NotLoaded;
    }

    /// `setDataBase`: opens the database at `file_path`. Fails only when no
    /// database is loaded afterwards (a database loaded before stays in use
    /// if this one cannot be opened, as in C++).
    pub fn set_data_base(&self, file_path: &str) -> Result<(), String> {
        #[cfg(feature = "maxmind")]
        let mut st = self.state.write().unwrap_or_else(|e| e.into_inner());
        #[cfg(not(feature = "maxmind"))]
        let st = self.state.read().unwrap_or_else(|e| e.into_inner());

        #[cfg(feature = "maxmind")]
        let mut int_max = String::new();

        #[cfg(feature = "maxmind")]
        match maxminddb::Reader::open_readfile(file_path) {
            Ok(reader) => {
                st.mmdb = Some(reader);
                st.version = GeoLookupVersion::VersionMaxmind;
            }
            Err(e) => {
                int_max = format!("libMaxMind: Can't open: {}.", mmdb_open_strerror(&e));
            }
        }

        if st.version == GeoLookupVersion::NotLoaded {
            let mut err = format!("Can't open:  {}. ", file_path);
            err.push_str("Support enabled for:");
            #[cfg(feature = "maxmind")]
            err.push_str(" libMaxMind");
            err.push('.');
            #[cfg(feature = "maxmind")]
            if !int_max.is_empty() {
                err.push(' ');
                err.push_str(&int_max);
            }
            return Err(err);
        }

        Ok(())
    }

    /// `lookup`: looks `target` up and fills the `GEO` collection of the
    /// transaction. Debug messages are only emitted with a transaction (the
    /// C++ code passes no debug callback without one).
    pub fn lookup(&self, target: &[u8], trans: Option<&mut Transaction<'_>>) -> bool {
        let st = self.state.read().unwrap_or_else(|e| e.into_inner());

        if st.version == GeoLookupVersion::NotLoaded {
            crate::ms_dbg_opt!(trans.as_deref(), 4, "Database is not open. Use: SecGeoLookupDb directive.");
            return false;
        }

        #[cfg(feature = "maxmind")]
        if st.version == GeoLookupVersion::VersionMaxmind {
            let Some(reader) = st.mmdb.as_ref() else {
                return false;
            };
            return maxmind_lookup(reader, target, trans);
        }

        #[cfg(not(feature = "maxmind"))]
        let _ = target;
        true
    }
}

/// `MMDB_strerror` of the status `MMDB_open` would have returned.
#[cfg(feature = "maxmind")]
fn mmdb_open_strerror(e: &maxminddb::MaxMindDbError) -> &'static str {
    match e {
        maxminddb::MaxMindDbError::Io(_) => "Error opening the specified MaxMind DB file",
        maxminddb::MaxMindDbError::InvalidDatabase { .. } => "The MaxMind DB file contains invalid metadata",
        _ => {
            "The MaxMind DB file is in a format this library can't handle (unknown record size or binary format version)"
        }
    }
}

/// `MMDB_lookup_string`'s address parsing: `getaddrinfo` with
/// `AI_NUMERICHOST`. Returns the address or the `gai_strerror` message.
#[cfg(feature = "maxmind")]
fn parse_numeric_host(target: &[u8]) -> Result<std::net::IpAddr, String> {
    use std::ffi::{CStr, CString};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    let end = target.iter().position(|&c| c == 0).unwrap_or(target.len());
    let host = CString::new(&target[..end]).unwrap_or_default();

    // SAFETY: an all-zero addrinfo is a valid "no hints" value.
    let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
    hints.ai_family = libc::AF_UNSPEC;
    hints.ai_flags = libc::AI_NUMERICHOST;
    hints.ai_socktype = libc::SOCK_STREAM;
    let mut res: *mut libc::addrinfo = std::ptr::null_mut();
    // SAFETY: `host` is NUL terminated, `hints` and `res` are valid; the
    // result list is freed below.
    let rc = unsafe { libc::getaddrinfo(host.as_ptr(), std::ptr::null(), &hints, &mut res) };
    if rc != 0 {
        // SAFETY: gai_strerror returns a static NUL terminated string.
        let msg = unsafe { CStr::from_ptr(libc::gai_strerror(rc)) }.to_string_lossy().into_owned();
        if !res.is_null() {
            // SAFETY: allocated by getaddrinfo.
            unsafe { libc::freeaddrinfo(res) };
        }
        return Err(msg);
    }
    // SAFETY: on success `res` points to at least one addrinfo whose
    // `ai_addr` matches `ai_family`.
    let ip = unsafe {
        let ai = &*res;
        let ip = if ai.ai_family == libc::AF_INET && !ai.ai_addr.is_null() {
            let sin = &*(ai.ai_addr as *const libc::sockaddr_in);
            Some(IpAddr::V4(Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes())))
        } else if ai.ai_family == libc::AF_INET6 && !ai.ai_addr.is_null() {
            let sin6 = &*(ai.ai_addr as *const libc::sockaddr_in6);
            Some(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)))
        } else {
            None
        };
        libc::freeaddrinfo(res);
        ip
    };
    // libmaxminddb rejects other families as an invalid lookup.
    ip.ok_or_else(|| "ai_family not supported".to_string())
}

#[cfg(feature = "maxmind")]
fn maxmind_lookup(reader: &maxminddb::Reader<Vec<u8>>, target: &[u8], trans: Option<&mut Transaction<'_>>) -> bool {
    use maxminddb::PathElement::Key;

    let ip = match parse_numeric_host(target) {
        Ok(ip) => ip,
        Err(msg) => {
            crate::ms_dbg_opt!(
                trans.as_deref(),
                4,
                "MaxMind: Error from getaddrinfo for: {}. {}",
                String::from_utf8_lossy(target),
                msg
            );
            return false;
        }
    };

    if ip.is_ipv6() && reader.metadata().ip_version == 4 {
        crate::ms_dbg_opt!(
            trans.as_deref(),
            4,
            "MaxMind: Got an error from libmaxminddb: You attempted to look up an IPv6 address in an IPv4-only database"
        );
        return false;
    }

    let r = match reader.lookup(ip) {
        Ok(r) => r,
        Err(_) => {
            crate::ms_dbg_opt!(
                trans.as_deref(),
                4,
                "MaxMind: Got an error from libmaxminddb: The MaxMind DB file's search tree is corrupt"
            );
            return false;
        }
    };

    if !r.has_data() {
        return false;
    }

    // The C++ code dereferences the transaction unconditionally here.
    let Some(t) = trans else {
        return true;
    };

    let strings: [(&[u8], &[maxminddb::PathElement<'_>]); 5] = [
        (b"COUNTRY_CODE", &[Key("country"), Key("iso_code")]),
        (b"COUNTRY_NAME", &[Key("country"), Key("names"), Key("en")]),
        (b"COUNTRY_CONTINENT", &[Key("continent"), Key("names"), Key("en")]),
        (b"CITY", &[Key("city"), Key("names"), Key("en")]),
        (b"POSTAL_CODE", &[Key("postal"), Key("code")]),
    ];
    for (name, path) in strings {
        if let Ok(Some(v)) = r.decode_path::<String>(path) {
            t.vars.geo.set(name, v.as_bytes(), 0);
        }
    }

    let doubles: [(&[u8], &[maxminddb::PathElement<'_>]); 2] =
        [(b"LATITUDE", &[Key("location"), Key("latitude")]), (b"LONGITUDE", &[Key("location"), Key("longitude")])];
    for (name, path) in doubles {
        if let Ok(Some(v)) = r.decode_path::<f64>(path) {
            // std::to_string(double)
            t.vars.geo.set(name, format!("{:.6}", v).as_bytes(), 0);
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One test only: the database is process wide.
    #[test]
    fn set_data_base_and_lookup() {
        let g = GeoLookup::get_instance();
        let err = g.set_data_base("/nonexistent/db.mmdb").unwrap_err();
        assert!(err.starts_with("Can't open:  /nonexistent/db.mmdb. Support enabled for:"));
        #[cfg(feature = "maxmind")]
        assert!(err.ends_with(" libMaxMind. libMaxMind: Can't open: Error opening the specified MaxMind DB file."));
        #[cfg(not(feature = "maxmind"))]
        assert!(err.ends_with("Support enabled for:."));
        assert!(!g.lookup(b"200.249.12.31", None));

        #[cfg(feature = "maxmind")]
        {
            use crate::modsecurity::ModSecurity;
            use crate::rules_set::RulesSet;

            let db = format!("{}/test/test-cases/data/GeoIP2-City-Test.mmdb", env!("CARGO_MANIFEST_DIR"));
            assert_eq!(g.set_data_base(&db), Ok(()));
            assert_eq!(g.version(), GeoLookupVersion::VersionMaxmind);

            let ms = ModSecurity::new();
            let rules = RulesSet::new();
            let mut t = Transaction::new(&ms, &rules, None);
            assert!(g.lookup(b"200.249.12.31", Some(&mut t)));
            let mut l = Vec::new();
            t.vars.geo.resolve(&mut l);
            let get = |k: &[u8]| l.iter().find(|v| v.key() == k).map(|v| v.value().to_vec());
            assert_eq!(get(b"COUNTRY_NAME"), Some(b"Brazil".to_vec()));
            assert_eq!(get(b"COUNTRY_CODE"), Some(b"BR".to_vec()));
            assert!(!g.lookup(b"www.modsecurity.org", None));
            assert!(!g.lookup(b"127.0.0.1", None));

            g.clean_up();
            assert_eq!(g.version(), GeoLookupVersion::NotLoaded);
        }
    }

    #[cfg(feature = "maxmind")]
    #[test]
    fn numeric_host_parsing() {
        assert_eq!(parse_numeric_host(b"127.0.0.1").unwrap(), "127.0.0.1".parse::<std::net::IpAddr>().unwrap());
        assert_eq!(parse_numeric_host(b"::1").unwrap(), "::1".parse::<std::net::IpAddr>().unwrap());
        assert!(parse_numeric_host(b"www.modsecurity.org").is_err());
    }
}
