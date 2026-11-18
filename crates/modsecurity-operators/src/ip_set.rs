//! The addresses and networks of an `@ipMatch` list ([`IpSet`]), used by
//! `@ipMatch`, `@ipMatchFromFile` and `@ipMatchF`.
//!
//! The entries of a list are read as the C++ code reads them
//! (`TreeAddIP`, see [`parse_entry`]: `atoi` CIDRs, a rejected `/0` and
//! explicit IPv6 `/128`, and the address syntax of `inet_pton`), so the same
//! lists load or fail.
//!
//! The networks are kept in prefix tries (the `prefix-trie` and `ipnet`
//! crates), and an address matches whenever a listed network contains it.
//! C++ keeps them in a crit-bit tree inherited from ModSecurity v2 that
//! misses addresses of a listed network when overlapping networks are
//! listed with it: an intentional deviation, see `MIGRATION.md`.

use std::io::Read;
use std::net::{Ipv4Addr, Ipv6Addr};

use modsecurity_compat::cnum::atoi;

/// The addresses and networks of an `@ipMatch` list.
#[derive(Debug, Default)]
pub struct IpSet {
    v4: prefix_trie::PrefixSet<ipnet::Ipv4Net>,
    v6: prefix_trie::PrefixSet<ipnet::Ipv6Net>,
}

impl IpSet {
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds the entries of `buffer`: one or more comma separated entries
    /// per line, `#` starts a comment. Returns `false` if an entry
    /// is invalid; there is no error message (the C code never fills one).
    pub fn add_from_buffer(&mut self, buffer: &[u8]) -> bool {
        // std::getline: a trailing newline does not produce an extra line.
        let mut lines: Vec<&[u8]> = buffer.split(|&c| c == b'\n').collect();
        if buffer.is_empty() || buffer.ends_with(b"\n") {
            lines.pop();
        }
        lines.into_iter().all(|line| {
            let line = match line.iter().position(|&c| c == b'#') {
                Some(p) => &line[..p],
                None => line,
            };
            self.add_entries(line)
        })
    }

    /// The result of loading entries: an invalid entry fails with an empty
    /// message, as in C++.
    fn loaded(ok: bool) -> Result<(), String> {
        if ok { Ok(()) } else { Err(String::new()) }
    }

    /// Adds the entries of the file `file`.
    pub fn add_from_file(&mut self, file: &str) -> Result<(), String> {
        let Ok(mut f) = std::fs::File::open(file) else {
            return Err(format!("Failed to open file: {}", file));
        };
        let mut content = Vec::new();
        // A read error ends the stream, like a failing std::getline.
        let _ = f.read_to_end(&mut content);
        Self::loaded(self.add_from_buffer(&content))
    }

    /// Adds the entries of `content` (a downloaded list).
    pub fn add_from_content(&mut self, content: &[u8]) -> Result<(), String> {
        Self::loaded(self.add_from_buffer(content))
    }

    /// Adds the comma separated entries of `entries` (up to a NUL byte);
    /// `false` when one is invalid: the ones before it stay.
    fn add_entries(&mut self, entries: &[u8]) -> bool {
        // strtok_r(..., ",") skips empty tokens.
        c_str(entries).split(|&c| c == b',').filter(|entry| !entry.is_empty()).all(|entry| self.add_entry(entry))
    }

    /// Adds an address or a network; `false` when it is invalid. An entry
    /// with a colon is an IPv6 one.
    fn add_entry(&mut self, entry: &[u8]) -> bool {
        if entry.contains(&b':') {
            let Some((address, cidr)) = parse_entry(entry, b':', parse_v6) else {
                return false;
            };
            // `parse_entry` only gives CIDRs 1..=128.
            self.v6.insert(ipnet::Ipv6Net::new_assert(address.into(), cidr).trunc());
        } else {
            let Some((address, cidr)) = parse_entry(entry, b'.', parse_v4) else {
                return false;
            };
            // `parse_entry` only gives CIDRs 1..=32.
            self.v4.insert(ipnet::Ipv4Net::new_assert(address.into(), cidr).trunc());
        }
        true
    }

    /// Whether `ip` (up to a NUL byte) is one of the addresses, or in one
    /// of the networks, of the set. Text that is not an address is in no
    /// set.
    pub fn contains(&self, ip: &[u8]) -> bool {
        let ip = c_str(ip);
        if ip.contains(&b':') {
            parse_v6(ip).is_some_and(|a| self.v6.get_spm(&ipnet::Ipv6Net::new_assert(a.into(), 128)).is_some())
        } else {
            parse_v4(ip).is_some_and(|a| self.v4.get_spm(&ipnet::Ipv4Net::new_assert(a.into(), 32)).is_some())
        }
    }
}

/// The C string view of `s` (up to its first NUL byte).
fn c_str(s: &[u8]) -> &[u8] {
    let end = s.iter().position(|&c| c == 0).unwrap_or(s.len());
    &s[..end]
}

/// Parses an IPv4 address as `inet_pton(AF_INET, ..)` does: strict dotted
/// decimal (no leading zeros, no short forms), which is also what `Ipv4Addr`
/// parses.
fn parse_v4(src: &[u8]) -> Option<[u8; 4]> {
    std::str::from_utf8(src).ok()?.parse::<Ipv4Addr>().ok().map(|a| a.octets())
}

/// Parses an IPv6 address as `inet_pton(AF_INET6, ..)` does.
fn parse_v6(src: &[u8]) -> Option<[u8; 16]> {
    std::str::from_utf8(src).ok()?.parse::<Ipv6Addr>().ok().map(|a| a.octets())
}

/// The address (of `N` bytes, read by `address`) and the CIDR of an entry
/// of a list, `address` or `address/cidr`, as the C++ `TreeAddIP` reads
/// it; `None` when the entry is invalid. `separator` is the separator of
/// the address family (`.` or `:`).
///
/// What C++ accepts decides which configurations load, so its ways are
/// kept:
/// - the entry is cut to the size of the C buffer: 31 bytes for IPv4, 127
///   for IPv6;
/// - the CIDR is read with `atoi` (`/24abc` is 24, `/abc` and `/` are 0),
///   and 0 is refused, as is a CIDR beyond the size of an address;
/// - a netmask written as an address (`/255.0.0.0`) is refused;
/// - an IPv6 entry with `/128` is refused (C++ leaves the `/128` in the
///   address it parses).
fn parse_entry<const N: usize>(
    entry: &[u8],
    separator: u8,
    address: fn(&[u8]) -> Option<[u8; N]>,
) -> Option<([u8; N], u8)> {
    let bits = N * 8;
    let entry = c_str(entry);
    let entry = &entry[..entry.len().min(bits - 1)];
    let Some(slash) = entry.iter().position(|&c| c == b'/') else {
        return Some((address(entry)?, bits as u8));
    };

    let mask = &entry[slash + 1..];
    if mask.contains(&separator) {
        return None;
    }
    let cidr = usize::try_from(atoi(mask)).ok().filter(|cidr| (1..=bits).contains(cidr))?;
    if cidr == 128 {
        return None;
    }
    Some((address(&entry[..slash])?, cidr as u8))
}

// The tests compare with the C library (`inet_pton`).
#[cfg(test)]
mod tests {
    use super::*;
    use modsecurity_native::testing::c_inet_pton;

    /// The std parsers accept exactly what `inet_pton` accepts, on valid
    /// addresses and on mutations of them.
    #[test]
    fn address_parsing_matches_inet_pton() {
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut next = move |n: usize| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed % n as u64) as usize
        };
        let v4_parts =
            ["0", "1", "9", "10", "127", "255", "256", "01", "001", "0x1", "", " ", "1e1", "-1", "999", "00"];
        let v6_parts =
            ["0", "1", "ff", "FFFF", "10000", "", "0000", "g", "1.2.3.4", "01.2.3.4", "::", "abcd", "00001", " "];
        let mut cases: Vec<String> = [
            "1.2.3.4",
            "1.2.3",
            "1.2.3.4.5",
            "1.2.3.4 ",
            " 1.2.3.4",
            "1..3.4",
            "::",
            "::1",
            "1::",
            ":::",
            "::ffff:1.2.3.4",
            "1:2:3:4:5:6:7:8",
            "1:2:3:4:5:6:7",
            "1:2:3:4:5:6:7:8:9",
            "1::2::3",
            "fe80::1%eth0",
            "::1.2.3",
            "1:2:3:4:5:6:1.2.3.4",
            "1:2:3:4:5:6:7:1.2.3.4",
            "::01.2.3.4",
            "[::1]",
            "0:0:0:0:0:0:0:0",
            "",
            ":",
            "1:",
            ":1",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        for _ in 0..20_000 {
            let n = 1 + next(6);
            cases.push((0..n).map(|_| v4_parts[next(v4_parts.len())]).collect::<Vec<_>>().join("."));
            let n = 1 + next(10);
            let sep = [":", "::"];
            let mut s = String::new();
            for i in 0..n {
                if i > 0 || next(8) == 0 {
                    s.push_str(sep[usize::from(next(6) == 0)]);
                }
                s.push_str(v6_parts[next(v6_parts.len())]);
            }
            cases.push(s);
        }
        for c in &cases {
            assert_eq!(parse_v4(c.as_bytes()).map(|a| a.to_vec()), c_inet_pton(libc::AF_INET, c.as_bytes()), "{c:?}");
            assert_eq!(parse_v6(c.as_bytes()).map(|a| a.to_vec()), c_inet_pton(libc::AF_INET6, c.as_bytes()), "{c:?}");
        }
    }

    /// The set of the entries of `param`; `None` when one is invalid.
    fn set(param: &str) -> Option<IpSet> {
        let mut set = IpSet::new();
        set.add_entries(param.as_bytes()).then_some(set)
    }

    fn tree(param: &str) -> IpSet {
        set(param).expect("valid param")
    }

    #[test]
    fn entry_parsing() {
        let v4 = |e: &str| parse_entry(e.as_bytes(), b'.', parse_v4);
        let v6 = |e: &str| parse_entry(e.as_bytes(), b':', parse_v6);
        assert_eq!(v4("1.2.3.4"), Some(([1, 2, 3, 4], 32)));
        assert_eq!(v4("1.2.3.4/24"), Some(([1, 2, 3, 4], 24)));
        assert_eq!(v4("1.2.3.4/32"), Some(([1, 2, 3, 4], 32)));
        // `atoi`: digits, then anything.
        assert_eq!(v4("1.2.3.4/24abc"), Some(([1, 2, 3, 4], 24)));
        assert_eq!(v4("1.2.3.4/+8"), Some(([1, 2, 3, 4], 8)));
        for refused in
            ["1.2.3.4/0", "1.2.3.4/33", "1.2.3.4/", "1.2.3.4/abc", "1.2.3.4/-1", "1.2.3.4/255.0.0.0", "1.2.3"]
        {
            assert_eq!(v4(refused), None, "{refused}");
        }
        // An entry is cut at 31 bytes: this CIDR is read as 2.
        assert_eq!(v4("100.100.100.100/0000000000000024").map(|(_, cidr)| cidr), Some(2));
        assert_eq!(v4("100.100.100.100/000000000000024").map(|(_, cidr)| cidr), Some(24));

        assert_eq!(v6("::1"), Some((std::net::Ipv6Addr::LOCALHOST.octets(), 128)));
        assert_eq!(v6("::1/64").map(|(_, cidr)| cidr), Some(64));
        assert_eq!(v6("::1/127").map(|(_, cidr)| cidr), Some(127));
        for refused in ["::1/128", "::1/129", "::1/0", "::1/ffff::", "::1/"] {
            assert_eq!(v6(refused), None, "{refused}");
        }
    }

    #[test]
    fn single_addresses() {
        let t = tree("192.168.1.1,10.0.0.1");
        assert!(t.contains(b"192.168.1.1"));
        assert!(t.contains(b"10.0.0.1"));
        assert!(!t.contains(b"10.0.0.2"));
        assert!(!t.contains(b"not an ip"));
    }

    #[test]
    fn networks() {
        let t = tree("192.168.0.0/16,10.0.0.0/8,2001:db8::/32");
        assert!(t.contains(b"192.168.200.3"));
        assert!(t.contains(b"10.255.0.1"));
        assert!(!t.contains(b"11.0.0.1"));
        assert!(t.contains(b"2001:db8::1"));
        assert!(!t.contains(b"2001:db9::1"));
    }

    #[test]
    fn invalid_entries() {
        assert!(set("1.2.3.4/0").is_none());
        assert!(set("1.2.3").is_none());
        // "/128" is not stripped from IPv6 entries.
        assert!(set("::1/128").is_none());
        // Empty tokens are skipped.
        assert!(set(",1.2.3.4,,").is_some());
    }

    #[test]
    fn host_bits_of_networks_are_ignored() {
        let t = tree("10.0.49.87/16,2001:db8::1:2/112");
        assert!(t.contains(b"10.0.0.1"));
        assert!(!t.contains(b"10.1.0.1"));
        assert!(t.contains(b"2001:db8::1:ffff"));
        assert!(!t.contains(b"2001:db8::2:0"));
    }

    /// An address of a listed network matches whatever other networks are
    /// listed. (The C++ crit-bit tree misses the last two addresses: see
    /// "Intentional deviations from C++" in MIGRATION.md.)
    #[test]
    fn overlapping_networks() {
        let t = tree("10.0.23.108/31,10.0.42.94/18,10.0.49.87/16,10.0.146.197/26,10.0.149.150/25");
        assert!(t.contains(b"10.0.49.87"));
        assert!(t.contains(b"10.0.23.108"));
        assert!(!t.contains(b"10.1.0.1"));
        assert!(t.contains(b"10.0.70.67"));
        assert!(t.contains(b"10.0.160.198"));
    }

    /// `contains` agrees with plain CIDR containment on random
    /// overlapping lists.
    #[test]
    fn matches_cidr_containment() {
        use rand::{Rng, SeedableRng};

        fn contains(nets: &[(u128, u8)], bits: u32, ip: u128) -> bool {
            nets.iter().any(|&(a, m)| {
                let shift = bits - u32::from(m);
                (a >> shift) == (ip >> shift)
            })
        }

        let mut rng = rand::rngs::StdRng::seed_from_u64(0x0069_706d_6174_6368);
        for v6 in [false, true] {
            let bits = if v6 { 128 } else { 32 };
            // Addresses differ in their low 16 bits only, so that the
            // networks overlap.
            let base: u128 = if v6 { 0x2001_0db8 << 96 } else { 0x0a00_0000 };
            let fmt = |a: u128| {
                if v6 {
                    std::net::Ipv6Addr::from(a).to_string()
                } else {
                    std::net::Ipv4Addr::from(a as u32).to_string()
                }
            };
            for _ in 0..5000 {
                let n = rng.random_range(1..8);
                let nets: Vec<(u128, u8)> = (0..n)
                    .map(|_| {
                        let a = base | u128::from(rng.random::<u16>());
                        // 127 at most: C++ does not accept an explicit /128.
                        let m = rng.random_range(bits - 16..bits.min(127) + 1) as u8;
                        (a, m)
                    })
                    .collect();
                let param = nets.iter().map(|&(a, m)| format!("{}/{}", fmt(a), m)).collect::<Vec<_>>().join(",");
                let t = tree(&param);
                for _ in 0..20 {
                    let ip = base | u128::from(rng.random::<u16>());
                    let want = contains(&nets, bits, ip);
                    assert_eq!(t.contains(fmt(ip).as_bytes()), want, "{param} {}", fmt(ip));
                }
            }
        }
    }

    #[test]
    fn buffer_with_comments_and_lines() {
        let mut t = IpSet::new();
        // The space before the comment is kept: not a valid address.
        assert!(!t.add_from_buffer(b"# comment\n127.0.0.1 # x\n10.0.0.0/8,::1\n\n"));
        let mut t = IpSet::new();
        assert!(t.add_from_buffer(b"# comment\n127.0.0.1#x\n10.0.0.0/8,::1\n\n"));
        assert!(t.contains(b"127.0.0.1"));
        assert!(t.contains(b"10.1.2.3"));
        assert!(t.contains(b"::1"));
        assert!(!t.contains(b"::2"));
        assert!(!t.contains(b"garbage"));
    }

    #[test]
    fn missing_file() {
        let mut t = IpSet::new();
        assert_eq!(t.add_from_file("/nonexistent/ips.txt"), Err("Failed to open file: /nonexistent/ips.txt".into()));
    }
}
