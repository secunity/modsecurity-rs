//! Port of `src/operators/rbl.cc`, `src/operators/rbl.h`.
//!
//! The DNS lookup uses the platform `getaddrinfo` (no hints, first result),
//! exactly as the C++ operator does.

use std::ffi::CString;
use std::net::Ipv4Addr;

use crate::collection::collection::Collection;
use crate::operators::operator::{Operator, Param};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;

/// `RblProvider`
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

/// The C string view of `s` (up to its first NUL byte).
fn c_str(s: &[u8]) -> &[u8] {
    let end = s.iter().position(|&c| c == 0).unwrap_or(s.len());
    &s[..end]
}

/// `sscanf(s, "%d.%d.%d.%d", ...) == 4`
fn scan_dotted_quad(s: &[u8]) -> Option<[i32; 4]> {
    let s = c_str(s);
    let mut pos = 0usize;
    let mut out = [0i32; 4];
    for (n, slot) in out.iter_mut().enumerate() {
        if n > 0 {
            if s.get(pos) != Some(&b'.') {
                return None;
            }
            pos += 1;
        }
        // %d: optional white space, optional sign, at least one digit.
        while pos < s.len() && matches!(s[pos], b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r') {
            pos += 1;
        }
        let mut neg = false;
        if pos < s.len() && (s[pos] == b'+' || s[pos] == b'-') {
            neg = s[pos] == b'-';
            pos += 1;
        }
        let start = pos;
        let mut v: i64 = 0;
        while pos < s.len() && s[pos].is_ascii_digit() {
            v = v.saturating_mul(10).saturating_add(i64::from(s[pos] - b'0'));
            pos += 1;
        }
        if pos == start {
            return None;
        }
        *slot = (if neg { -v } else { v }) as i32;
    }
    Some(out)
}

impl Rbl {
    pub fn new(param: RunTimeString) -> Self {
        let param = Param::new(param);
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

    /// `mapIpToAddress`: the DNS name to query for `ip_str` (empty when the
    /// lookup cannot be done).
    pub fn map_ip_to_address(&self, ip_str: &[u8], trans: Option<&Transaction<'_>>) -> Vec<u8> {
        let key: Vec<u8> =
            trans.and_then(|t| t.rules.properties.httpbl_key.as_deref()).unwrap_or_default().as_bytes().to_vec();

        let Some([h0, h1, h2, h3]) = scan_dotted_quad(ip_str) else {
            crate::ms_dbg_opt!(
                trans,
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
            crate::ms_dbg_opt!(
                trans,
                0,
                "Missing RBL key, cannot continue with the operator execution, please set the key using: SecHttpBlKey"
            );
            return Vec::new();
        }

        let mut addr = format!("{}.{}.{}.{}.", h3, h2, h1, h0).into_bytes();
        addr.extend_from_slice(&self.service);

        if self.demands_password {
            let mut a = key;
            a.push(b'.');
            a.extend_from_slice(&addr);
            addr = a;
        }

        addr
    }

    /// `futherInfo_httpbl`
    fn further_info_httpbl(sin_addr: Ipv4Addr, ip_str: &str, trans: Option<&Transaction<'_>>) {
        // inet_ntoa + sscanf("%d.%d.%d.%d")
        let [first, days, score, ty] = sin_addr.octets();

        if first != 127 {
            crate::ms_dbg_opt!(trans, 4, "RBL lookup of {} failed: bad response", ip_str);
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

        // The literal "%s" is part of the C++ message.
        crate::ms_dbg_opt!(
            trans,
            4,
            "RBL lookup of {} succeeded. %s: {} days since last activity, threat score {}. Case: {}",
            ip_str,
            days,
            score,
            ptype
        );
    }

    /// `futherInfo_spamhaus`
    fn further_info_spamhaus(high8bits: u32, ip_str: &str, trans: Option<&Transaction<'_>>) {
        match high8bits {
            2 | 3 => crate::ms_dbg_opt!(trans, 4, "RBL lookup of {} succeeded (Static UBE sources).", ip_str),
            4..=7 => crate::ms_dbg_opt!(trans, 4, "RBL lookup of {} succeeded (Illegal 3rd party exploits).", ip_str),
            10 | 11 => crate::ms_dbg_opt!(
                trans,
                4,
                "RBL lookup of {} succeeded (Delivering unauthenticated SMTP email).",
                ip_str
            ),
            _ => crate::ms_dbg_opt!(trans, 4, "RBL lookup of {} succeeded ", ip_str),
        }
    }

    /// `futherInfo_uribl`
    fn further_info_uribl(high8bits: u32, ip_str: &str, trans: Option<&Transaction<'_>>) {
        match high8bits {
            2 => crate::ms_dbg_opt!(trans, 4, "RBL lookup of {} succeeded (BLACK).", ip_str),
            4 => crate::ms_dbg_opt!(trans, 4, "RBL lookup of {} succeeded (GREY).", ip_str),
            8 => crate::ms_dbg_opt!(trans, 4, "RBL lookup of {} succeeded (RED).", ip_str),
            14 => crate::ms_dbg_opt!(trans, 4, "RBL lookup of {} succeeded (BLACK,GREY,RED).", ip_str),
            255 => crate::ms_dbg_opt!(trans, 4, "RBL lookup of {} succeeded (DNS IS BLOCKED).", ip_str),
            _ => crate::ms_dbg_opt!(trans, 4, "RBL lookup of {} succeeded (WHITE).", ip_str),
        }
    }

    /// `furtherInfo`
    fn further_info(sin_addr: Ipv4Addr, ip_str: &str, trans: Option<&Transaction<'_>>, provider: RblProvider) {
        // `sin->sin_addr.s_addr >> 24`: s_addr is in network byte order,
        // read as a host integer (the last octet on little endian hosts).
        let high8bits = u32::from_ne_bytes(sin_addr.octets()) >> 24;

        match provider {
            RblProvider::UnknownProvider => crate::ms_dbg_opt!(trans, 2, "RBL lookup of {} succeeded.", ip_str),
            RblProvider::Httpbl => Self::further_info_httpbl(sin_addr, ip_str, trans),
            RblProvider::Uribl => Self::further_info_uribl(high8bits, ip_str, trans),
            RblProvider::Spamhaus => Self::further_info_spamhaus(high8bits, ip_str, trans),
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
    let Ok(c_host) = CString::new(c_str(host)) else {
        return Resolved::Failed;
    };
    let mut info: *mut libc::addrinfo = std::ptr::null_mut();
    // SAFETY: `c_host` is NUL terminated, null service and hints are
    // allowed; the result list is freed below.
    let rc = unsafe { libc::getaddrinfo(c_host.as_ptr(), std::ptr::null(), std::ptr::null(), &mut info) };
    if rc != 0 {
        if !info.is_null() {
            // SAFETY: allocated by getaddrinfo.
            unsafe { libc::freeaddrinfo(info) };
        }
        return Resolved::Failed;
    }
    if info.is_null() {
        return Resolved::Failed;
    }
    // SAFETY: on success `info` points to a valid addrinfo whose `ai_addr`
    // (when non-null) is a sockaddr of family `sa_family`.
    unsafe {
        let addr = (*info).ai_addr;
        let r = if addr.is_null() {
            Resolved::Failed
        } else if i32::from((*addr).sa_family) == libc::AF_INET {
            let sin = &*(addr as *const libc::sockaddr_in);
            Resolved::V4(Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes()))
        } else {
            Resolved::OtherFamily(i32::from((*addr).sa_family))
        };
        libc::freeaddrinfo(info);
        r
    }
}

impl Operator for Rbl {
    fn name(&self) -> &'static str {
        "Rbl"
    }

    fn param(&self) -> Option<&Param> {
        Some(&self.param)
    }
    fn evaluate(
        &self,
        t: &mut Transaction<'_>,
        rule: &RuleWithActions,
        ip_str: &[u8],
        _rm: &mut RuleMessage<'_>,
    ) -> bool {
        let host = self.map_ip_to_address(ip_str, Some(&*t));
        let ip_s = String::from_utf8_lossy(ip_str).into_owned();

        if host.is_empty() {
            return false;
        }

        match resolve(&host) {
            Resolved::Failed => {
                crate::ms_dbg_a!(t, 5, "RBL lookup of {} failed.", ip_s);
                return false;
            }
            Resolved::OtherFamily(family) => {
                crate::ms_dbg_a!(t, 7, "Unsupported address family: {}", family);
                return false;
            }
            Resolved::V4(sin_addr) => {
                Self::further_info(sin_addr, &ip_s, Some(&*t), self.provider);
            }
        }

        if rule.has_capture_action() {
            t.collections.tx_collection.store_or_update_first(b"0", ip_str);
            crate::ms_dbg_a!(t, 7, "Added RXL match TX.0: {}", ip_s);
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dotted_quad() {
        assert_eq!(scan_dotted_quad(b"1.2.3.4"), Some([1, 2, 3, 4]));
        assert_eq!(scan_dotted_quad(b" 1. 2.3.4xyz"), Some([1, 2, 3, 4]));
        assert_eq!(scan_dotted_quad(b"1.2.3"), None);
        assert_eq!(scan_dotted_quad(b"a.b.c.d"), None);
        assert_eq!(scan_dotted_quad(b"1 .2.3.4"), None);
    }

    #[test]
    fn map_ip() {
        let op = Rbl::new(RunTimeString::from_text("sbl-xbl.spamhaus.org"));
        assert_eq!(op.provider, RblProvider::Spamhaus);
        assert_eq!(op.map_ip_to_address(b"1.2.3.4", None), b"4.3.2.1.sbl-xbl.spamhaus.org".to_vec());
        assert_eq!(op.map_ip_to_address(b"example.com", None), b"example.com.sbl-xbl.spamhaus.org".to_vec());
        let op = Rbl::new(RunTimeString::from_text("dnsbl.httpbl.org"));
        assert!(op.map_ip_to_address(b"1.2.3.4", None).is_empty());
    }
}
