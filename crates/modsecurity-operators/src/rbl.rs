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
}

/// What a list's `answer` (the address its DNS name resolved to) says:
/// `Ok` with the debug log level and what the log says after "RBL lookup
/// of ... succeeded", or `Err` with why it is not a listing.
///
/// Lists answer within 127.0.0.0/8 (RFC 5782); any other address comes
/// from a resolver that rewrites unknown names, not from the list. Within
/// it, uribl.com and spamhaus.org also answer when they refuse a query
/// (most often one sent through a public resolver): those error codes are
/// not listings either.
fn read_answer(provider: RblProvider, answer: Ipv4Addr) -> Result<(u8, String), &'static str> {
    let [first, second, third, last] = answer.octets();
    if first != 127 {
        return Err("the answer is not in 127.0.0.0/8, so it does not come from the list");
    }
    let info = match provider {
        RblProvider::UnknownProvider => return Ok((2, ".".to_string())),
        RblProvider::Httpbl => {
            // 127.days.score.type
            let kind = match last {
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
            // The literal "%s" is part of the message: the debug log text of
            // the original ModSecurity, kept as it is.
            format!(". %s: {second} days since last activity, threat score {third}. Case: {kind}")
        }
        RblProvider::Uribl => match last {
            1 => return Err("uribl.com refused the query (127.0.0.1)"),
            255 => return Err("uribl.com refused the query (DNS IS BLOCKED)"),
            _ => {
                let lists: Vec<&str> = [(2, "BLACK"), (4, "GREY"), (8, "RED")]
                    .iter()
                    .filter(|(bit, _)| last & bit != 0)
                    .map(|(_, name)| *name)
                    .collect();
                if lists.is_empty() { " (WHITE).".to_string() } else { format!(" ({}).", lists.join(",")) }
            }
        },
        RblProvider::Spamhaus if [second, third] == [255, 255] => {
            return Err(match last {
                252 => "spamhaus.org refused the query: the list name is wrong (127.255.255.252)",
                254 => "spamhaus.org refused the query: it does not answer public resolvers (127.255.255.254)",
                255 => "spamhaus.org refused the query: too many queries (127.255.255.255)",
                _ => "spamhaus.org answered with an error code (127.255.255.x)",
            });
        }
        RblProvider::Spamhaus => match last {
            2 | 3 => " (Static UBE sources).".to_string(),
            4..=7 => " (Illegal 3rd party exploits).".to_string(),
            10 | 11 => " (Delivering unauthenticated SMTP email).".to_string(),
            _ => " ".to_string(),
        },
    };
    Ok((4, info))
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
            Resolved::V4(answer) => match read_answer(self.provider, answer) {
                Ok((level, info)) => crate::ms_dbg!(cx, level, "RBL lookup of {} succeeded{}", ip_s, info),
                Err(why) => {
                    crate::ms_dbg!(cx, 4, "RBL lookup of {} failed: {}.", ip_s, why);
                    return false;
                }
            },
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

    /// Only answers in 127.0.0.0/8 are listings, and the error codes of
    /// uribl.com and spamhaus.org are not. (C++ took any answer as a
    /// listing: through a public resolver, uribl.com answers 127.0.0.1 to
    /// every query, so every value matched.)
    #[test]
    fn refusals_and_foreign_answers_are_not_listings() {
        let read = |provider, a: [u8; 4]| read_answer(provider, Ipv4Addr::from(a));
        for provider in [RblProvider::UnknownProvider, RblProvider::Httpbl, RblProvider::Uribl, RblProvider::Spamhaus] {
            assert!(read(provider, [10, 0, 0, 1]).is_err(), "{provider:?}");
            assert!(read(provider, [93, 184, 216, 34]).is_err(), "{provider:?}");
        }
        assert_eq!(read(RblProvider::Uribl, [127, 0, 0, 1]), Err("uribl.com refused the query (127.0.0.1)"));
        assert!(read(RblProvider::Uribl, [127, 0, 0, 255]).is_err());
        for code in [252, 253, 254, 255] {
            assert!(read(RblProvider::Spamhaus, [127, 255, 255, code]).is_err());
        }
    }

    #[test]
    fn listings_and_their_log_text() {
        let read = |provider, a: [u8; 4]| read_answer(provider, Ipv4Addr::from(a)).unwrap();
        assert_eq!(read(RblProvider::UnknownProvider, [127, 0, 0, 2]), (2, ".".to_string()));
        assert_eq!(read(RblProvider::Uribl, [127, 0, 0, 2]).1, " (BLACK).");
        assert_eq!(read(RblProvider::Uribl, [127, 0, 0, 6]).1, " (BLACK,GREY).");
        assert_eq!(read(RblProvider::Uribl, [127, 0, 0, 14]).1, " (BLACK,GREY,RED).");
        assert_eq!(read(RblProvider::Spamhaus, [127, 0, 0, 2]).1, " (Static UBE sources).");
        assert_eq!(read(RblProvider::Spamhaus, [127, 0, 0, 10]).1, " (Delivering unauthenticated SMTP email).");
        assert_eq!(
            read(RblProvider::Httpbl, [127, 3, 20, 1]).1,
            ". %s: 3 days since last activity, threat score 20. Case: Suspicious IP"
        );
    }
}
