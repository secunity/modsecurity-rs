//! The `@rbl` operator: looks the input (an IPv4 address or a domain) up
//! in a DNS block list.
//!
//! The DNS lookup uses the platform `getaddrinfo` (no hints, first
//! result).

use std::net::{Ipv4Addr, SocketAddr};

use crate::{Context, Operator, Param};

/// The block list service, recognized from the parameter. It decides
/// whether an access key is needed and how an answer is logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RblProvider {
    UnknownProvider,
    /// httpbl.org
    Httpbl,
    /// uribl.com
    Uribl,
    /// spamhaus.org
    Spamhaus,
}

#[derive(Debug)]
pub struct Rbl {
    param: Param,
    service: Vec<u8>,
    demands_password: bool,
    provider: RblProvider,
}

/// The IPv4 address `value` is, if it is exactly one (four numbers from 0
/// to 255, nothing around them).
fn ipv4_address(value: &[u8]) -> Option<Ipv4Addr> {
    std::str::from_utf8(value).ok()?.parse().ok()
}

impl Rbl {
    pub fn new(param: Param) -> Self {
        let service = param.literal.clone();
        let contains = |needle: &[u8]| service.windows(needle.len()).any(|w| w == needle);
        let (demands_password, provider) = if contains(b"httpbl.org") {
            (true, RblProvider::Httpbl)
        } else if contains(b"uribl.com") {
            (false, RblProvider::Uribl)
        } else if contains(b"spamhaus.org") {
            (false, RblProvider::Spamhaus)
        } else {
            (false, RblProvider::UnknownProvider)
        };
        Rbl { param, service, demands_password, provider }
    }

    /// The DNS name to query for `ip_str` (empty when the
    /// lookup cannot be done).
    pub fn map_ip_to_address(&self, ip_str: &[u8], cx: &dyn Context) -> Vec<u8> {
        let key: Vec<u8> = cx.httpbl_key().to_vec();

        let Some(ip) = ipv4_address(ip_str) else {
            crate::ms_dbg!(
                cx,
                0,
                "Failed to understand `{}' as a valid IP address, assuming domain format input",
                String::from_utf8_lossy(ip_str)
            );
            let mut addr = ip_str.to_vec();
            addr.push(b'.');
            addr.extend_from_slice(&self.service);
            return addr;
        };

        if self.demands_password && key.is_empty() {
            crate::ms_dbg!(
                cx,
                0,
                "Missing RBL key, cannot continue with the operator execution, please set the key using: SecHttpBlKey"
            );
            return Vec::new();
        }

        let [h0, h1, h2, h3] = ip.octets();
        let mut addr = format!("{h3}.{h2}.{h1}.{h0}.").into_bytes();
        addr.extend_from_slice(&self.service);

        if self.demands_password {
            let mut a = key;
            a.push(b'.');
            a.extend_from_slice(&addr);
            addr = a;
        }

        addr
    }

    /// Logs an httpbl.org answer: days since last activity, threat score
    /// and visitor type.
    fn further_info_httpbl(sin_addr: Ipv4Addr, ip_str: &str, cx: &dyn Context) {
        // inet_ntoa + sscanf("%d.%d.%d.%d")
        let [first, days, score, ty] = sin_addr.octets();

        if first != 127 {
            crate::ms_dbg!(cx, 4, "RBL lookup of {} failed: bad response", ip_str);
            return;
        }

        let ptype = match ty {
            0 => "Search Engine",
            1 => "Suspicious IP",
            2 => "Harvester IP",
            3 => "Suspicious harvester IP",
            4 => "Comment spammer IP",
            5 => "Suspicious comment spammer IP",
            6 => "Harvester and comment spammer IP",
            7 => "Suspicious harvester comment spammer IP",
            _ => " ",
        };

        // The literal "%s" is part of the message: the debug log text of the
        // original ModSecurity, kept as it is.
        crate::ms_dbg!(
            cx,
            4,
            "RBL lookup of {} succeeded. %s: {} days since last activity, threat score {}. Case: {}",
            ip_str,
            days,
            score,
            ptype
        );
    }

    /// Logs the spamhaus.org list named by the answer.
    fn further_info_spamhaus(high8bits: u32, ip_str: &str, cx: &dyn Context) {
        match high8bits {
            2 | 3 => crate::ms_dbg!(cx, 4, "RBL lookup of {} succeeded (Static UBE sources).", ip_str),
            4..=7 => crate::ms_dbg!(cx, 4, "RBL lookup of {} succeeded (Illegal 3rd party exploits).", ip_str),
            10 | 11 => {
                crate::ms_dbg!(cx, 4, "RBL lookup of {} succeeded (Delivering unauthenticated SMTP email).", ip_str)
            }
            _ => crate::ms_dbg!(cx, 4, "RBL lookup of {} succeeded ", ip_str),
        }
    }

    /// Logs the uribl.com list named by the answer.
    fn further_info_uribl(high8bits: u32, ip_str: &str, cx: &dyn Context) {
        match high8bits {
            2 => crate::ms_dbg!(cx, 4, "RBL lookup of {} succeeded (BLACK).", ip_str),
            4 => crate::ms_dbg!(cx, 4, "RBL lookup of {} succeeded (GREY).", ip_str),
            8 => crate::ms_dbg!(cx, 4, "RBL lookup of {} succeeded (RED).", ip_str),
            14 => crate::ms_dbg!(cx, 4, "RBL lookup of {} succeeded (BLACK,GREY,RED).", ip_str),
            255 => crate::ms_dbg!(cx, 4, "RBL lookup of {} succeeded (DNS IS BLOCKED).", ip_str),
            _ => crate::ms_dbg!(cx, 4, "RBL lookup of {} succeeded (WHITE).", ip_str),
        }
    }

    /// Logs a successful lookup, with the details the provider gives.
    fn further_info(sin_addr: Ipv4Addr, ip_str: &str, cx: &dyn Context, provider: RblProvider) {
        // `sin->sin_addr.s_addr >> 24`: s_addr is in network byte order,
        // read as a host integer (the last octet on little endian hosts).
        let high8bits = u32::from_ne_bytes(sin_addr.octets()) >> 24;

        match provider {
            RblProvider::UnknownProvider => crate::ms_dbg!(cx, 2, "RBL lookup of {} succeeded.", ip_str),
            RblProvider::Httpbl => Self::further_info_httpbl(sin_addr, ip_str, cx),
            RblProvider::Uribl => Self::further_info_uribl(high8bits, ip_str, cx),
            RblProvider::Spamhaus => Self::further_info_spamhaus(high8bits, ip_str, cx),
        }
    }
}

/// Result of resolving a name with `getaddrinfo` (first entry only).
enum Resolved {
    Failed,
    V4(Ipv4Addr),
    OtherFamily(i32),
}

/// `getaddrinfo(host, NULL, NULL, &info)` and the family/address of the
/// first returned entry.
fn resolve(host: &[u8]) -> Resolved {
    let Ok(host) = std::str::from_utf8(host) else {
        return Resolved::Failed;
    };
    let first = dns_lookup::getaddrinfo(Some(host), None, None).ok().and_then(|mut entries| entries.next());
    match first {
        Some(Ok(info)) => match info.sockaddr {
            SocketAddr::V4(a) => Resolved::V4(*a.ip()),
            SocketAddr::V6(_) => Resolved::OtherFamily(info.address),
        },
        _ => Resolved::Failed,
    }
}

impl Operator for Rbl {
    fn name(&self) -> &'static str {
        "Rbl"
    }

    fn param(&self) -> Option<&Param> {
        Some(&self.param)
    }
    fn evaluate(&self, cx: &mut dyn Context, ip_str: &[u8]) -> bool {
        let host = self.map_ip_to_address(ip_str, cx);
        let ip_s = String::from_utf8_lossy(ip_str).into_owned();

        if host.is_empty() {
            return false;
        }

        match resolve(&host) {
            Resolved::Failed => {
                crate::ms_dbg!(cx, 5, "RBL lookup of {} failed.", ip_s);
                return false;
            }
            Resolved::OtherFamily(family) => {
                crate::ms_dbg!(cx, 7, "Unsupported address family: {}", family);
                return false;
            }
            Resolved::V4(sin_addr) => {
                Self::further_info(sin_addr, &ip_s, cx, self.provider);
            }
        }

        if cx.captures() {
            cx.set_capture(b"0", ip_str.to_vec());
            crate::ms_dbg!(cx, 7, "Added RXL match TX.0: {}", ip_s);
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A value is an address only when it is exactly one; C++ read it with
    /// `sscanf("%d.%d.%d.%d")`, which also took spaces, signs, numbers
    /// above 255 and text after the address.
    #[test]
    fn only_a_whole_ipv4_address_is_an_address() {
        assert_eq!(ipv4_address(b"1.2.3.4"), Some(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(ipv4_address(b"255.0.0.255"), Some(Ipv4Addr::new(255, 0, 0, 255)));
        for not_one in [
            &b" 1. 2.3.4xyz"[..],
            b" 1.2.3.4",
            b"1.2.3.4 ",
            b"1.2.3.4:80",
            b"1.2.3.4, 5.6.7.8",
            b"+1.2.3.4",
            b"-1.2.3.4",
            b"999.1.1.1",
            b"01.2.3.4",
            b"1.2.3",
            b"a.b.c.d",
            b"",
        ] {
            assert_eq!(ipv4_address(not_one), None, "{:?}", String::from_utf8_lossy(not_one));
        }
    }

    #[test]
    fn a_value_that_is_not_an_address_is_looked_up_as_a_domain() {
        let op = Rbl::new(Param::from_text("zen.spamhaus.org"));
        assert_eq!(map(&op, b"1.2.3.4:80", None), b"1.2.3.4:80.zen.spamhaus.org".to_vec());
        assert_eq!(map(&op, b"999.1.1.1", None), b"999.1.1.1.zen.spamhaus.org".to_vec());
    }

    /// `op.map_ip_to_address(ip)` with `SecHttpBlKey` set to `key`.
    fn map(op: &Rbl, ip: &[u8], key: Option<&str>) -> Vec<u8> {
        let cx = crate::test_support::TestContext {
            httpbl_key: key.unwrap_or_default().as_bytes().to_vec(),
            ..Default::default()
        };
        op.map_ip_to_address(ip, &cx)
    }

    #[test]
    fn map_ip() {
        let op = Rbl::new(Param::from_text("sbl-xbl.spamhaus.org"));
        assert_eq!(op.provider, RblProvider::Spamhaus);
        assert_eq!(map(&op, b"1.2.3.4", None), b"4.3.2.1.sbl-xbl.spamhaus.org".to_vec());
        assert_eq!(map(&op, b"example.com", None), b"example.com.sbl-xbl.spamhaus.org".to_vec());
        let op = Rbl::new(Param::from_text("dnsbl.httpbl.org"));
        // httpbl.org needs SecHttpBlKey.
        assert!(map(&op, b"1.2.3.4", None).is_empty());
        assert_eq!(map(&op, b"1.2.3.4", Some("abcdefghijkl")), b"abcdefghijkl.4.3.2.1.dnsbl.httpbl.org".to_vec());
    }
}
