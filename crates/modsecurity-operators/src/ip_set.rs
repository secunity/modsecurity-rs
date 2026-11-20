//! The addresses and networks of an `@ipMatch` list ([`IpSet`]), used by
//! `@ipMatch`, `@ipMatchFromFile` and `@ipMatchF`.
//!
//! An entry of a list is an address or `address/length` ([`parse_entry`]),
//! with the address syntax of `inet_pton`. The networks are kept in prefix
//! tries (the `prefix-trie` and `ipnet` crates), and an address matches
//! whenever a listed network contains it.
//!
//! Both differ from C++ on purpose (see "Intentional deviations from C++"
//! in `MIGRATION.md`): C++ keeps the networks in a crit-bit tree inherited
//! from ModSecurity v2 that misses addresses when networks overlap, and
//! reads entries with C habits (`atoi`, fixed buffers) that refuse `/0`
//! and `::1/128` and accept `/24abc`.

use std::io::Read;
use std::net::IpAddr;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};

/// The addresses and networks of an `@ipMatch` list.
#[derive(Debug, Default)]
pub struct IpSet {
    v4: prefix_trie::PrefixSet<Ipv4Net>,
    v6: prefix_trie::PrefixSet<Ipv6Net>,
}

impl IpSet {
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds the entries of `buffer`: any number of comma separated entries
    /// per line, with or without spaces around them; `#` starts a comment,
    /// and lines may end with a carriage return. Returns `false` if an
    /// entry is invalid; there is no error message saying which one.
    pub fn add_from_buffer(&mut self, buffer: &[u8]) -> bool {
        // A trailing newline does not produce an extra (empty) line.
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
    /// message.
    fn loaded(ok: bool) -> Result<(), String> {
        if ok { Ok(()) } else { Err(String::new()) }
    }

    /// Adds the entries of the file `file`.
    pub fn add_from_file(&mut self, file: &str) -> Result<(), String> {
        let Ok(mut f) = std::fs::File::open(file) else {
            return Err(format!("Failed to open file: {}", file));
        };
        let mut content = Vec::new();
        // A read error is not reported: what was read so far is used.
        let _ = f.read_to_end(&mut content);
        Self::loaded(self.add_from_buffer(&content))
    }

    /// Adds the entries of `content` (a downloaded list).
    pub fn add_from_content(&mut self, content: &[u8]) -> Result<(), String> {
        Self::loaded(self.add_from_buffer(content))
    }

    /// Adds the comma separated entries of `entries`, without the
    /// whitespace around each (empty ones are skipped); `false` when one
    /// is invalid: the ones before it stay.
    fn add_entries(&mut self, entries: &[u8]) -> bool {
        entries
            .split(|&c| c == b',')
            .map(<[u8]>::trim_ascii)
            .filter(|entry| !entry.is_empty())
            .all(|entry| self.add_entry(entry))
    }

    /// Adds an address or a network; `false` when it is invalid.
    fn add_entry(&mut self, entry: &[u8]) -> bool {
        match parse_entry(entry) {
            Some(IpNet::V4(net)) => self.v4.insert(net),
            Some(IpNet::V6(net)) => self.v6.insert(net),
            None => return false,
        };
        true
    }

    /// Whether `ip` is one of the addresses, or in one of the networks, of
    /// the set. Text that is not exactly an address is in no set.
    pub fn contains(&self, ip: &[u8]) -> bool {
        match parse_address(ip) {
            Some(IpAddr::V4(a)) => self.v4.get_spm(&Ipv4Net::from(a)).is_some(),
            Some(IpAddr::V6(a)) => self.v6.get_spm(&Ipv6Net::from(a)).is_some(),
            None => false,
        }
    }
}

/// An IPv4 or IPv6 address, written as `inet_pton` reads them: strict
/// dotted decimal (no leading zeros, no short forms), and the forms of
/// RFC 4291 for IPv6. That is what the standard library parses.
fn parse_address(text: &[u8]) -> Option<IpAddr> {
    std::str::from_utf8(text).ok()?.parse().ok()
}

/// An entry of a list: `address`, or `address/length` for the network of
/// the addresses that share the first `length` bits (0 to 32 for IPv4, 0
/// to 128 for IPv6, in decimal digits). `None` when the entry is neither.
fn parse_entry(entry: &[u8]) -> Option<IpNet> {
    let Some(slash) = entry.iter().position(|&c| c == b'/') else {
        return parse_address(entry).map(IpNet::from);
    };
    let address = parse_address(&entry[..slash])?;
    let length = &entry[slash + 1..];
    if length.is_empty() || !length.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let length = std::str::from_utf8(length).ok()?.parse().ok()?;
    // The address of the network: the host bits of the entry are dropped.
    IpNet::new(address, length).ok().map(|net| net.trunc())
}

// The tests compare with the C library (`inet_pton`).
#[cfg(test)]
mod tests {
    use super::*;
    use modsecurity_native::testing::c_inet_pton;

    /// An address is what `inet_pton` accepts, on valid addresses and on
    /// mutations of them.
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
            let (v4, v6) = match parse_address(c.as_bytes()) {
                Some(IpAddr::V4(a)) => (Some(a.octets().to_vec()), None),
                Some(IpAddr::V6(a)) => (None, Some(a.octets().to_vec())),
                None => (None, None),
            };
            assert_eq!(v4, c_inet_pton(libc::AF_INET, c.as_bytes()), "{c:?}");
            assert_eq!(v6, c_inet_pton(libc::AF_INET6, c.as_bytes()), "{c:?}");
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
        let net = |e: &str| parse_entry(e.as_bytes()).map(|n| n.to_string());
        let is = |n: &str| Some(n.to_string());
        assert_eq!(net("1.2.3.4"), is("1.2.3.4/32"));
        assert_eq!(net("1.2.3.4/32"), is("1.2.3.4/32"));
        // The host bits are dropped.
        assert_eq!(net("1.2.3.4/24"), is("1.2.3.0/24"));
        assert_eq!(net("1.2.3.4/024"), is("1.2.3.0/24"));
        assert_eq!(net("1.2.3.4/0"), is("0.0.0.0/0"));
        assert_eq!(net("::1"), is("::1/128"));
        assert_eq!(net("::1/128"), is("::1/128"));
        assert_eq!(net("2001:db8::1/64"), is("2001:db8::/64"));
        assert_eq!(net("::/0"), is("::/0"));
        // However long the entry is.
        assert_eq!(
            net("0000:0000:0000:0000:0000:0000:0000:0001/0000000000000000000000000000000000000128"),
            is("::1/128")
        );

        for refused in [
            "",
            "1.2.3",
            "01.2.3.4",
            " 1.2.3.4",
            "1.2.3.4 ",
            "1.2.3.4/",
            "1.2.3.4/33",
            "1.2.3.4/abc",
            "1.2.3.4/24abc",
            "1.2.3.4/+8",
            "1.2.3.4/-1",
            "1.2.3.4/ 8",
            "1.2.3.4/255.0.0.0",
            "1.2.3.4/24/5",
            "::1/129",
            "::1/ffff::",
            "fe80::1%eth0",
        ] {
            assert_eq!(net(refused), None, "{refused:?}");
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
        assert!(set("1.2.3.4/33").is_none());
        assert!(set("1.2.3").is_none());
        // The entries before an invalid one are not kept by the operator:
        // the rule does not load.
        assert!(set("1.2.3.4,nonsense").is_none());
        // Empty tokens are skipped.
        assert!(set(",1.2.3.4,,").is_some());
    }

    /// `/0` is every address of the family, and of that family only.
    #[test]
    fn everything() {
        let t = tree("0.0.0.0/0");
        assert!(t.contains(b"1.2.3.4") && t.contains(b"255.255.255.255"));
        assert!(!t.contains(b"::1"));
        let t = tree("::/0,10.0.0.1");
        assert!(t.contains(b"::1") && t.contains(b"2001:db8::1") && t.contains(b"10.0.0.1"));
        assert!(!t.contains(b"10.0.0.2"));
        // A whole network and one of its addresses, in either order.
        assert!(tree("::1/128,::/0").contains(b"::2"));
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
                        // 127 at most: an explicit /128 is covered by the tests above.
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
        assert!(t.add_from_buffer(b"# comment\n127.0.0.1 # x\n10.0.0.0/8,::1\n\n"));
        assert!(t.contains(b"127.0.0.1"));
        assert!(t.contains(b"10.1.2.3"));
        assert!(t.contains(b"::1"));
        assert!(!t.contains(b"::2"));
        assert!(!t.contains(b"garbage"));
    }

    /// Whitespace around an entry is not part of it: after a comma, before
    /// a comment, at the end of a line of a file with CRLF line endings.
    #[test]
    fn whitespace_around_entries() {
        let t = tree(" 1.2.3.4 ,\t10.0.0.0/8 , ,::1\t");
        assert!(t.contains(b"1.2.3.4") && t.contains(b"10.9.9.9") && t.contains(b"::1"));
        let mut t = IpSet::new();
        assert!(t.add_from_buffer(b"127.0.0.1\r\n  10.0.0.0/8   # office\r\n\r\n# all\r\n::1\r\n"));
        assert!(t.contains(b"127.0.0.1") && t.contains(b"10.1.2.3") && t.contains(b"::1"));
        // Inside an entry it is an error.
        assert!(set("1.2.3.4 /8").is_none());
        assert!(set("1.2.3.4/ 8").is_none());
        assert!(set("1.2. 3.4").is_none());
    }

    /// A NUL byte is not the end of the text: an entry with one is not an
    /// entry, and a value with one is not an address.
    #[test]
    fn nul_bytes() {
        assert!(set("1.2.3.4\0").is_none());
        assert!(set("1.2.3.4\0,5.6.7.8").is_none());
        let t = tree("1.2.3.4");
        assert!(t.contains(b"1.2.3.4"));
        assert!(!t.contains(b"1.2.3.4\0"));
        assert!(!t.contains(b"1.2.3.4\0junk"));
        // Nor is whitespace around a value ignored.
        assert!(!t.contains(b" 1.2.3.4"));
    }

    #[test]
    fn missing_file() {
        let mut t = IpSet::new();
        assert_eq!(t.add_from_file("/nonexistent/ips.txt"), Err("Failed to open file: /nonexistent/ips.txt".into()));
    }
}
