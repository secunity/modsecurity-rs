//! The geolocation database of `SecGeoLookupDb`, used by `@geoLookup`.
//!
//! Each rule set owns the database its configuration names (C++ keeps one
//! database per process). MaxMind databases are read with the `maxminddb`
//! crate when the `maxmind` feature is enabled (C++ `WITH_MAXMIND`). The
//! legacy GeoIP library is not available, so this behaves like a C++ build
//! without `WITH_GEOIP`.

use crate::transaction::Transaction;

/// An open geolocation database.
#[derive(Debug)]
pub struct GeoDb {
    #[cfg(feature = "maxmind")]
    reader: maxminddb::Reader<Vec<u8>>,
}

impl GeoDb {
    /// Opens the database at `file_path`.
    pub fn open(file_path: &str) -> Result<GeoDb, String> {
        #[cfg(feature = "maxmind")]
        let int_max = match maxminddb::Reader::open_readfile(file_path) {
            Ok(reader) => return Ok(GeoDb { reader }),
            Err(e) => format!("libMaxMind: Can't open: {}.", mmdb_open_strerror(&e)),
        };

        let mut err = format!("Can't open:  {}. ", file_path);
        err.push_str("Support enabled for:");
        #[cfg(feature = "maxmind")]
        {
            err.push_str(" libMaxMind.");
            err.push(' ');
            err.push_str(&int_max);
        }
        #[cfg(not(feature = "maxmind"))]
        err.push('.');
        Err(err)
    }

    /// Looks `target` up and fills the `GEO` collection of the transaction.
    /// Debug messages are only emitted with a transaction (the C++ code
    /// passes no debug callback without one).
    pub fn lookup(&self, target: &[u8], trans: Option<&mut Transaction<'_>>) -> bool {
        #[cfg(feature = "maxmind")]
        return maxmind_lookup(&self.reader, target, trans);
        #[cfg(not(feature = "maxmind"))]
        {
            // No database can be opened without a library.
            let _ = (target, trans);
            false
        }
    }

    /// `lookup` without a database (no `SecGeoLookupDb`).
    pub fn not_loaded(trans: &Transaction<'_>) -> bool {
        crate::ms_dbg_a!(trans, 4, "Database is not open. Use: SecGeoLookupDb directive.");
        false
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
    use dns_lookup::{AddrInfoHints, SockType, getaddrinfo};

    let end = target.iter().position(|&c| c == 0).unwrap_or(target.len());
    // A name that is not text cannot be a numeric address.
    let host = std::str::from_utf8(&target[..end]).unwrap_or("\u{fffd}");
    let hints = AddrInfoHints {
        flags: libc::AI_NUMERICHOST,
        address: libc::AF_UNSPEC,
        socktype: SockType::Stream.into(),
        protocol: 0,
    };
    let mut entries = getaddrinfo(Some(host), None, Some(hints)).map_err(|e| gai_message(e.error_num()))?;
    match entries.next() {
        Some(Ok(info)) => Ok(info.sockaddr.ip()),
        // libmaxminddb rejects other families as an invalid lookup.
        _ => Err("ai_family not supported".to_string()),
    }
}

/// `gai_strerror(code)`
#[cfg(feature = "maxmind")]
fn gai_message(code: i32) -> String {
    // SAFETY: gai_strerror returns a static NUL terminated string.
    unsafe { std::ffi::CStr::from_ptr(libc::gai_strerror(code)) }.to_string_lossy().into_owned()
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

    #[test]
    fn open_and_lookup() {
        let err = GeoDb::open("/nonexistent/db.mmdb").unwrap_err();
        assert!(err.starts_with("Can't open:  /nonexistent/db.mmdb. Support enabled for:"));
        #[cfg(feature = "maxmind")]
        assert!(err.ends_with(" libMaxMind. libMaxMind: Can't open: Error opening the specified MaxMind DB file."));
        #[cfg(not(feature = "maxmind"))]
        assert!(err.ends_with("Support enabled for:."));

        #[cfg(feature = "maxmind")]
        {
            use crate::modsecurity::ModSecurity;
            use crate::rules_set::RulesSet;

            let db = format!("{}/test/test-cases/data/GeoIP2-City-Test.mmdb", env!("CARGO_MANIFEST_DIR"));
            let g = GeoDb::open(&db).unwrap();

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
