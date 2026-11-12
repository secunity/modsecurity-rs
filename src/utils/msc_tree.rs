//! Port of `src/utils/msc_tree.cc`, `src/utils/msc_tree.h`.
//!
//! The crit-bit (radix) tree inherited from ModSecurity v2 that backs
//! `@ipMatch`, `@ipMatchFromFile` and `@ipMatchF`.
//!
//! The C code links `TreeNode`s with raw pointers (`left`, `right`,
//! `parent`); here every [`CptTree`] owns its nodes in an arena and the links
//! are indexes. The algorithms are translated as they are, quirks included,
//! because they decide which addresses match:
//!
//! * the netmask arrays are re-allocated (zero filled) every time a netmask
//!   is added to a node, so only the newest netmask of a node survives, the
//!   others become 0;
//! * adding a prefix that already exists with another netmask is ignored;
//! * the netblock search applies the netmask of the first entry of a node
//!   only (the byte index is not reset between entries).
//!
//! Together these make an address that lies in a listed network go
//! unmatched when other, overlapping networks are listed next to it (for
//! example `@ipMatch 10.0.49.87/16,10.0.42.94/18` does not match
//! `10.0.70.67`; C++ v3 behaves the same).
//!
//! With the `ipmatch-prefix-trie` feature (off by default, not a C++
//! option), [`TreeRoot`] stores the networks in prefix tries (the
//! `prefix-trie` and `ipnet` crates) instead: entries are still parsed and
//! rejected exactly as by `TreeAddIP` ([`parse_ipv4`], [`parse_ipv6`]), but an
//! address matches whenever any listed network contains it.
//!
//! Reads past the end of the prefix buffers that the C code performs in
//! branches whose outcome does not depend on the value read are replaced by
//! their (constant) outcome; see the comments at those places.

use std::net::{Ipv4Addr, Ipv6Addr};

pub const IPV4_TREE: i32 = 0x1;
pub const IPV6_TREE: i32 = 0x2;

pub const IPV4_LEN: u32 = 0x20;
pub const IPV6_LEN: u32 = 0x80;

const NETMASK_256: u32 = 0x100;
const NETMASK_128: u32 = 0x80;
const NETMASK_32: u32 = 0x20;
const NETMASK_8: u32 = 0x8;
const NETMASK_2: u32 = 0x2;

/// `SHIFT_LEFT_MASK(x)`: `(int)(~0U << x)`.
#[inline]
fn shift_left_mask(x: u32) -> i32 {
    (!0u32).wrapping_shl(x) as i32
}

/// `SHIFT_RIGHT_MASK(x, y)` with `x = NETMASK_128`: the bit of `bit` within
/// its byte.
#[inline]
fn bit_in_byte(bit: u32) -> u8 {
    (NETMASK_128 >> (bit % 8)) as u8
}

/// `TREE_CHECK(buffer[bit >> 3], bit mask)`
#[inline]
fn tree_check(buffer: &[u8], bit: u32) -> bool {
    buffer.get((bit >> 3) as usize).copied().unwrap_or(0) & bit_in_byte(bit) != 0
}

/// `TreePrefix`: the address bytes of a node and its list of netmasks
/// (the `CPTData` linked list, kept as a vector in list order).
#[derive(Debug, Clone)]
pub struct TreePrefix {
    pub buffer: Vec<u8>,
    pub bitlen: u32,
    pub prefix_data: Vec<u8>,
}

impl TreePrefix {
    /// `CPTCreatePrefix` (+ `InsertDataPrefix`): `None` when `ip_bitmask`
    /// is not a multiple of 8.
    fn create(ipdata: &[u8], ip_bitmask: u32, netmask: u8) -> Option<TreePrefix> {
        if !ip_bitmask.is_multiple_of(8) {
            return None;
        }
        let bytes = (ip_bitmask / 8) as usize;
        let mut buffer = vec![0u8; bytes];
        let n = bytes.min(ipdata.len());
        buffer[..n].copy_from_slice(&ipdata[..n]);
        Some(TreePrefix { buffer, bitlen: ip_bitmask, prefix_data: vec![netmask] })
    }

    /// `CPTAppendToCPTDataList`: inserts `netmask` keeping the list sorted
    /// by decreasing netmask.
    fn append_to_data_list(&mut self, netmask: u8) {
        let pos = self.prefix_data.iter().position(|&nm| netmask > nm).unwrap_or(self.prefix_data.len());
        self.prefix_data.insert(pos, netmask);
    }

    /// `TreePrefixContainNetmask`
    pub fn contains_netmask(&self, netmask: u8) -> bool {
        self.prefix_data.contains(&netmask)
    }

    /// `TreePrefixNetmask`: with `flag` only the first netmask of the list
    /// is considered (`TreeCheckData` otherwise).
    fn netmask(&self, netmask: u32, flag: bool) -> bool {
        if flag {
            return match self.prefix_data.first() {
                None => false,
                Some(&nm) => u32::from(nm) == netmask,
            };
        }
        self.prefix_data.iter().any(|&nm| u32::from(nm) == netmask)
    }
}

/// `TreeNode`
#[derive(Debug, Default, Clone)]
pub struct TreeNode {
    pub bit: u32,
    pub count: i32,
    /// `None` is the C null pointer; the vector may be longer than `count`.
    pub netmasks: Option<Vec<u8>>,
    pub prefix: Option<TreePrefix>,
    pub left: Option<usize>,
    pub right: Option<usize>,
    pub parent: Option<usize>,
}

/// `CPTTree`: owns its nodes (arena, indexes are node handles).
#[derive(Debug, Default)]
pub struct CptTree {
    pub count: i32,
    pub head: Option<usize>,
    nodes: Vec<TreeNode>,
}

/// `TreeRoot`
///
/// With the `ipmatch-prefix-trie` feature the networks are kept in prefix
/// tries instead of [`CptTree`]s: entries are parsed and validated as in C++,
/// but an address matches whenever any listed network contains it (see the
/// module documentation).
#[derive(Debug, Default)]
pub struct TreeRoot {
    #[cfg(not(feature = "ipmatch-prefix-trie"))]
    pub ipv4_tree: CptTree,
    #[cfg(not(feature = "ipmatch-prefix-trie"))]
    pub ipv6_tree: CptTree,
    #[cfg(feature = "ipmatch-prefix-trie")]
    ipv4_set: prefix_trie::PrefixSet<ipnet::Ipv4Net>,
    #[cfg(feature = "ipmatch-prefix-trie")]
    ipv6_set: prefix_trie::PrefixSet<ipnet::Ipv6Net>,
}

/// `ConvertIPNetmask`: clears the host bits of `buffer`.
fn convert_ip_netmask(buffer: &mut [u8], netmask: u8, ip_bitmask: u32) {
    let bytes = (ip_bitmask / 8) as usize;
    let netmask = u32::from(netmask);
    for (aux, b) in buffer.iter_mut().enumerate().take(bytes) {
        let mask_bit = (1 + aux as u32) * 8;
        let mask = if mask_bit > netmask {
            if (mask_bit - netmask) < 8 { shift_left_mask(mask_bit - netmask) } else { 0 }
        } else {
            -1
        };
        *b &= mask as u8;
    }
}

/// `CheckBitmask`
fn check_bitmask(netmask: u8, ip_bitmask: u32) -> bool {
    match netmask {
        0xff => true,
        0x20 => ip_bitmask == 0x20,
        0x80 => ip_bitmask == 0x80,
        _ => false,
    }
}

/// Inserts `netmask` into a fresh (zero filled, as `malloc` + `memset` in
/// the C code) netmask array of `count` entries, keeping it sorted by
/// decreasing value.
fn fresh_netmasks_with(count: i32, netmask: u8) -> Vec<u8> {
    let count = count as usize;
    let mut nm = vec![0u8; count];
    if count - 1 == 0 {
        nm[0] = netmask;
        return nm;
    }
    nm[count - 1] = netmask;
    let mut i = count as isize - 2;
    while i >= 0 {
        let iu = i as usize;
        if netmask < nm[iu] {
            nm[iu + 1] = netmask;
            break;
        }
        nm[iu + 1] = nm[iu];
        nm[iu] = netmask;
        i -= 1;
    }
    nm
}

impl CptTree {
    /// `CPTCreateRadixTree`
    pub fn new() -> Self {
        Self::default()
    }

    /// Access to a node by handle.
    pub fn node(&self, n: usize) -> &TreeNode {
        &self.nodes[n]
    }

    /// `CPTCreateNode`
    fn create_node(&mut self) -> usize {
        self.nodes.push(TreeNode::default());
        self.nodes.len() - 1
    }

    /// `CPTCreateHead`
    fn create_head(&mut self, prefix: TreePrefix, node: usize, netmask: u8, ip_bitmask: u32) -> Option<usize> {
        let n = &mut self.nodes[node];
        n.bit = prefix.bitlen;
        n.prefix = Some(prefix);
        self.head = Some(node);
        if check_bitmask(netmask, ip_bitmask) {
            return Some(node);
        }
        let n = &mut self.nodes[node];
        n.count += 1;
        let mut nm = vec![0u8; n.count as usize];
        nm[0] = netmask;
        n.netmasks = Some(nm);
        Some(node)
    }

    /// `SetParentNode`: replaces `node` by `new_node` in its parent (or as
    /// the head).
    fn set_parent_node(&mut self, node: usize, new_node: usize) -> usize {
        match self.nodes[node].parent {
            None => self.head = Some(new_node),
            Some(p) => {
                if self.nodes[p].right == Some(node) {
                    self.nodes[p].right = Some(new_node);
                } else {
                    self.nodes[p].left = Some(new_node);
                }
            }
        }
        new_node
    }

    /// Walks up from `node` while `netmask < parent->bit + 1`.
    fn climb_for_netmask(&self, mut node: usize, netmask: u8) -> usize {
        let mut parent = self.nodes[node].parent;
        while let Some(p) = parent {
            // C: `while (netmask < parent->bit + 1)`
            if u32::from(netmask) > self.nodes[p].bit {
                break;
            }
            node = p;
            parent = self.nodes[p].parent;
        }
        node
    }

    /// `InsertNetmask`
    fn insert_netmask(&mut self, new_node: usize, netmask: u8, bitlen: u8) -> i32 {
        let nm32 = u32::from(netmask);
        if nm32 != NETMASK_256 - 1 && nm32 != NETMASK_128 && (nm32 != NETMASK_32 || u32::from(bitlen) != NETMASK_32) {
            let node = self.climb_for_netmask(new_node, netmask);
            let n = &mut self.nodes[node];
            n.count += 1;
            let first = n.count - 1 == 0;
            n.netmasks = Some(fresh_netmasks_with(n.count, netmask));
            if first {
                return 1;
            }
        }
        0
    }

    /// `CPTAddElement`: adds `ipdata` (`ip_bitmask` bits) with `netmask`.
    /// `ipdata` is masked in place, as in C.
    pub fn add_element(&mut self, ipdata: &mut [u8], ip_bitmask: u32, netmask: u8) -> Option<usize> {
        convert_ip_netmask(ipdata, netmask, ip_bitmask);

        let prefix = TreePrefix::create(ipdata, ip_bitmask, netmask)?;

        let Some(head) = self.head else {
            let node = self.create_node();
            return self.create_head(prefix, node, netmask, ip_bitmask);
        };

        let mut node = head;
        let buffer = prefix.buffer.clone();
        // `unsigned char bitlen = prefix->bitlen;`
        let bitlen = prefix.bitlen as u8;
        let bitlen32 = u32::from(bitlen);

        while self.nodes[node].bit < bitlen32 || self.nodes[node].prefix.is_none() {
            let n = &self.nodes[node];
            let next = if bitlen32 < n.bit || tree_check(&buffer, n.bit) { n.right } else { n.left };
            match next {
                None => break,
                Some(x) => node = x,
            }
        }

        let bottom_node = node;
        // The C code dereferences the bottom node prefix unconditionally;
        // the descent always ends on a node with a prefix.
        let bottom_buffer = self.nodes[bottom_node].prefix.as_ref()?.buffer.clone();

        let bit_validation: i32 =
            if self.nodes[node].bit < bitlen32 { self.nodes[node].bit as i32 } else { i32::from(bitlen) };

        let mut test_bit: i32 = 0;
        let mut i: usize = 0;
        while (i as i32 * NETMASK_8 as i32) < bit_validation {
            let mut temp = i32::from(buffer[i] ^ bottom_buffer[i]);
            if temp == 0 {
                test_bit = (i as i32 + 1) * NETMASK_8 as i32;
                i += 1;
                continue;
            }
            temp += temp;
            let mut cnt = 0;
            let mut net = NETMASK_256 as i32;
            let mut div = 2;
            while net >= NETMASK_2 as i32 {
                if temp >= net {
                    test_bit = (i as i32 * NETMASK_8 as i32) + cnt;
                    break;
                }
                net = NETMASK_256 as i32 / div;
                div += div;
                cnt += 1;
            }
            break;
        }

        if bit_validation < test_bit {
            test_bit = bit_validation;
        }

        let mut parent = self.nodes[node].parent;
        while let Some(p) = parent {
            if (test_bit as u32) > self.nodes[p].bit {
                break;
            }
            node = p;
            parent = self.nodes[node].parent;
        }

        if test_bit == i32::from(bitlen) && self.nodes[node].bit == bitlen32 {
            match self.nodes[node].prefix.as_ref() {
                Some(node_prefix) => {
                    let found = node_prefix.prefix_data.iter().filter(|&&nm| nm == netmask).count();
                    if found != 0 {
                        // The C code appends the new netmask to the list of
                        // the freshly created (and then discarded) prefix,
                        // not to the one of the node.
                        let mut discarded = prefix;
                        discarded.append_to_data_list(netmask);

                        if check_bitmask(netmask, ip_bitmask) {
                            return Some(node);
                        }

                        let node = self.climb_for_netmask(node, netmask);
                        let n = &mut self.nodes[node];
                        n.count += 1;
                        n.netmasks = Some(fresh_netmasks_with(n.count, netmask));
                        return Some(node);
                    }
                }
                None => {
                    self.nodes[node].prefix =
                        TreePrefix::create(&prefix.buffer, prefix.bitlen, (NETMASK_256 - 1) as u8);
                }
            }
            return Some(node);
        }

        let new_node = self.create_node();
        self.nodes[new_node].bit = prefix.bitlen;
        self.nodes[new_node].prefix = Some(prefix);

        if test_bit == i32::from(bitlen) {
            // Unreachable in practice (a leaf always has `bit == bitlen`);
            // the C code would read one byte past the prefix buffer here,
            // `tree_check` reads it as 0.
            if tree_check(&bottom_buffer, test_bit as u32) {
                self.nodes[new_node].right = Some(node);
            } else {
                self.nodes[new_node].left = Some(node);
            }
            self.nodes[new_node].parent = self.nodes[node].parent;
            let p = self.set_parent_node(node, new_node);
            self.nodes[node].parent = Some(p);
        } else {
            let i_node = self.create_node();
            self.nodes[i_node].bit = test_bit as u32;
            self.nodes[i_node].parent = self.nodes[node].parent;

            if let Some(nm) = self.nodes[node].netmasks.clone() {
                let count = self.nodes[node].count as usize;
                let mut i = 0;
                while i < count {
                    if i32::from(nm[i]) < test_bit + 1 {
                        break;
                    }
                    i += 1;
                }
                // `malloc(count - i)`: non-null even for 0 entries.
                self.nodes[i_node].netmasks = Some(nm[i..count].to_vec());
                self.nodes[i_node].count = (count - i) as i32;
                self.nodes[node].count = i as i32;
                if i == 0 {
                    self.nodes[node].netmasks = None;
                }
            }

            if tree_check(&buffer, test_bit as u32) {
                self.nodes[i_node].left = Some(node);
                self.nodes[i_node].right = Some(new_node);
            } else {
                self.nodes[i_node].left = Some(new_node);
                self.nodes[i_node].right = Some(node);
            }

            self.nodes[new_node].parent = Some(i_node);
            let p = self.set_parent_node(node, i_node);
            self.nodes[node].parent = Some(p);
        }

        self.insert_netmask(new_node, netmask, bitlen);
        Some(new_node)
    }

    /// `CPTRetriveNode`
    fn retrive_node(&self, buffer: &[u8], ip_bitmask: u32, node: Option<usize>) -> Option<usize> {
        let mut node = node?;
        while self.nodes[node].bit < ip_bitmask {
            let n = &self.nodes[node];
            node = if tree_check(buffer, n.bit) { n.right? } else { n.left? };
        }
        Some(node)
    }

    /// `CPTRetriveParentNode`
    fn retrive_parent_node(&self, mut node: Option<usize>) -> Option<usize> {
        while let Some(n) = node {
            if self.nodes[n].netmasks.is_some() {
                break;
            }
            node = self.nodes[n].parent;
        }
        node
    }

    /// `CPTFindElementIPNetblock` (the C tail recursion on the parent of
    /// the netmask node is a loop here). `ipdata` is masked in place.
    fn find_element_ip_netblock(&self, ipdata: &mut [u8], ip_bitmask: u8, mut node: Option<usize>) -> Option<usize> {
        let ip_bitmask32 = u32::from(ip_bitmask);
        loop {
            let netmask_node = self.retrive_parent_node(node)?;
            let mut cur = netmask_node;
            let nn = &self.nodes[netmask_node];
            let netmasks = nn.netmasks.as_deref().unwrap_or(&[]);
            let mut i: usize = 0;
            let mut j: usize = 0;
            while (j as i32) < nn.count {
                let bytes = (ip_bitmask / 8) as usize;
                let nmj = u32::from(netmasks[j]);
                // Note: `i` is not reset for the following netmasks.
                while i < bytes {
                    let mut mask: i32 = -1;
                    let mask_bits = (i as u32 + 1) * 8;
                    if mask_bits > nmj {
                        mask = if (mask_bits - nmj) < 8 { shift_left_mask(mask_bits - nmj) } else { 0 };
                    }
                    ipdata[i] &= mask as u8;
                    i += 1;
                }

                cur = self.retrive_node(ipdata, ip_bitmask32, Some(cur))?;

                let n = &self.nodes[cur];
                if n.bit != ip_bitmask32 {
                    return None;
                }
                let prefix = n.prefix.as_ref()?;

                if prefix.buffer[..bytes] == ipdata[..bytes] {
                    // The C code checks the netmask once when `ip_bitmask %
                    // 8 == 0` and once more after comparing the trailing
                    // bits with `SHIFT_LEFT_MASK(8 - ip_bitmask % 8)`; for
                    // the 32/128 bit trees that mask has no low bits, the
                    // comparison is always true and both checks are the same.
                    if prefix.netmask(nmj, false) {
                        return Some(cur);
                    }
                }
                j += 1;
            }
            node = self.nodes[netmask_node].parent;
        }
    }

    /// `CPTFindElement`
    fn find_element(&self, ipdata: &[u8], ip_bitmask: u32) -> Option<usize> {
        let head = self.head?;

        if ip_bitmask > (NETMASK_256 - 1) {
            return None;
        }

        let bytes = (ip_bitmask / 8) as usize;
        let mut temp_data = [0u8; (NETMASK_256 - 1) as usize];
        let n = bytes.min(ipdata.len());
        temp_data[..n].copy_from_slice(&ipdata[..n]);

        let node = self.retrive_node(&temp_data, ip_bitmask, Some(head))?;

        let nd = &self.nodes[node];
        if nd.bit != ip_bitmask {
            return None;
        }

        let Some(prefix) = nd.prefix.as_ref() else {
            return Some(node);
        };

        if nd.netmasks.is_none() && prefix.buffer[..bytes] == temp_data[..bytes] {
            // See `find_element_ip_netblock` about the second, identical,
            // check of the C code.
            if prefix.netmask(ip_bitmask, true) {
                return Some(node);
            }
        }

        self.find_element_ip_netblock(&mut temp_data, ip_bitmask as u8, Some(node))
    }

    /// `CPTIpMatch`
    pub fn ip_match(&self, ipdata: &[u8], ty: i32) -> Option<usize> {
        match ty {
            IPV4_TREE => self.find_element(ipdata, NETMASK_32),
            IPV6_TREE => self.find_element(ipdata, NETMASK_128),
            _ => None,
        }
    }

    /// `TreeAddIP`: `buffer` is an address with an optional `/cidr`.
    pub fn add_ip(&mut self, buffer: &[u8], ty: i32) -> Option<usize> {
        match ty {
            IPV4_TREE => {
                let (mut addr4, netmask_v4) = parse_ipv4(buffer)?;
                self.count += 1;
                self.add_element(&mut addr4, NETMASK_32, netmask_v4)
            }
            IPV6_TREE => {
                let (mut addr6, netmask_v6) = parse_ipv6(buffer)?;
                self.count += 1;
                self.add_element(&mut addr6, NETMASK_128, netmask_v6)
            }
            _ => None,
        }
    }
}

/// The parsing half of `TreeAddIP` for `IPV4_TREE`: the address and CIDR of
/// `buffer` (an address with an optional `/cidr`), `None` when invalid.
pub fn parse_ipv4(buffer: &[u8]) -> Option<([u8; 4], u8)> {
    let buffer = c_str(buffer);
    // `strchr(buffer, '/') - buffer`. Without a `/` the C code computes
    // a meaningless position that never truncates the address.
    let pos = buffer.iter().position(|&c| c == b'/');

    // `char ip_strv4[NETMASK_32]` filled with `strncpy`.
    let mut ip_strv4 = buffer[..buffer.len().min(NETMASK_32 as usize - 1)].to_vec();
    let netmask_v4 = is_netmask_v4(&ip_strv4);
    if u32::from(netmask_v4) > NETMASK_32 {
        return None;
    }
    if netmask_v4 == 0 {
        return None;
    } else if let Some(p) = pos.filter(|&p| p < ip_strv4.len()) {
        ip_strv4.truncate(p);
    }
    Some((parse_v4(&ip_strv4)?, netmask_v4))
}

/// The parsing half of `TreeAddIP` for `IPV6_TREE`: the address and CIDR of
/// `buffer` (an address with an optional `/cidr`), `None` when invalid.
pub fn parse_ipv6(buffer: &[u8]) -> Option<([u8; 16], u8)> {
    let buffer = c_str(buffer);
    let pos = buffer.iter().position(|&c| c == b'/');

    let mut ip_strv6 = buffer[..buffer.len().min(NETMASK_128 as usize - 1)].to_vec();
    let netmask_v6 = is_netmask_v6(&ip_strv6);
    if u32::from(netmask_v6) > NETMASK_128 {
        return None;
    }
    if netmask_v6 == 0 {
        return None;
    } else if u32::from(netmask_v6) != NETMASK_128
        && let Some(p) = pos.filter(|&p| p < ip_strv6.len())
    {
        ip_strv6.truncate(p);
    }
    Some((parse_v6(&ip_strv6)?, netmask_v6))
}

impl TreeRoot {
    /// `create_radix_tree`
    pub fn new() -> Self {
        Self::default()
    }

    /// `tree_contains_ip`: 1 when `value` is in the tree, 0 when it is not
    /// and -1 when `value` is not a valid address.
    pub fn contains_ip(&self, value: &[u8]) -> i32 {
        let value = c_str(value);
        if !value.contains(&b':') {
            let Some(in4) = parse_v4(value) else {
                return -1;
            };
            if self.match_ipv4(&in4) {
                return 1;
            }
        } else {
            let Some(in6) = parse_v6(value) else {
                return -1;
            };
            if self.match_ipv6(&in6) {
                return 1;
            }
        }
        0
    }

    /// `add_ip_from_param`: adds the comma separated addresses/networks of
    /// `param`; 0 on success, -1 when an entry cannot be added.
    pub fn add_ip_from_param(&mut self, param: &[u8]) -> i32 {
        let param = c_str(param);
        // strtok_r(..., ",") skips empty tokens.
        for s in param.split(|&c| c == b',').filter(|s| !s.is_empty()) {
            let added = if !s.contains(&b':') { self.add_ipv4(s) } else { self.add_ipv6(s) };
            if !added {
                return -1;
            }
        }
        0
    }

    /// `ip_tree_from_param`: a new tree holding the entries of `param`.
    pub fn from_param(param: &[u8]) -> Option<TreeRoot> {
        let mut t = TreeRoot::new();
        if t.add_ip_from_param(param) != 0 {
            return None;
        }
        Some(t)
    }

    /// `TreeAddIP(..., tree->ipv4_tree, IPV4_TREE) != NULL`
    #[cfg(not(feature = "ipmatch-prefix-trie"))]
    fn add_ipv4(&mut self, s: &[u8]) -> bool {
        self.ipv4_tree.add_ip(s, IPV4_TREE).is_some()
    }

    /// `TreeAddIP(..., tree->ipv6_tree, IPV6_TREE) != NULL`
    #[cfg(not(feature = "ipmatch-prefix-trie"))]
    fn add_ipv6(&mut self, s: &[u8]) -> bool {
        self.ipv6_tree.add_ip(s, IPV6_TREE).is_some()
    }

    /// `CPTIpMatch(..., tree->ipv4_tree, IPV4_TREE) != NULL`
    #[cfg(not(feature = "ipmatch-prefix-trie"))]
    fn match_ipv4(&self, in4: &[u8; 4]) -> bool {
        self.ipv4_tree.ip_match(in4, IPV4_TREE).is_some()
    }

    /// `CPTIpMatch(..., tree->ipv6_tree, IPV6_TREE) != NULL`
    #[cfg(not(feature = "ipmatch-prefix-trie"))]
    fn match_ipv6(&self, in6: &[u8; 16]) -> bool {
        self.ipv6_tree.ip_match(in6, IPV6_TREE).is_some()
    }

    #[cfg(feature = "ipmatch-prefix-trie")]
    fn add_ipv4(&mut self, s: &[u8]) -> bool {
        let Some((addr4, netmask_v4)) = parse_ipv4(s) else {
            return false;
        };
        // The parser only returns CIDRs 1..=32.
        let net = ipnet::Ipv4Net::new_assert(addr4.into(), netmask_v4).trunc();
        self.ipv4_set.insert(net);
        true
    }

    #[cfg(feature = "ipmatch-prefix-trie")]
    fn add_ipv6(&mut self, s: &[u8]) -> bool {
        let Some((addr6, netmask_v6)) = parse_ipv6(s) else {
            return false;
        };
        // The parser only returns CIDRs 1..=128.
        let net = ipnet::Ipv6Net::new_assert(addr6.into(), netmask_v6).trunc();
        self.ipv6_set.insert(net);
        true
    }

    /// Whether any IPv4 network of the set contains `in4`.
    #[cfg(feature = "ipmatch-prefix-trie")]
    fn match_ipv4(&self, in4: &[u8; 4]) -> bool {
        self.ipv4_set.get_spm(&ipnet::Ipv4Net::new_assert((*in4).into(), 32)).is_some()
    }

    /// Whether any IPv6 network of the set contains `in6`.
    #[cfg(feature = "ipmatch-prefix-trie")]
    fn match_ipv6(&self, in6: &[u8; 16]) -> bool {
        self.ipv6_set.get_spm(&ipnet::Ipv6Net::new_assert((*in6).into(), 128)).is_some()
    }
}

/// The C string view of `s` (up to its first NUL byte).
fn c_str(s: &[u8]) -> &[u8] {
    let end = s.iter().position(|&c| c == 0).unwrap_or(s.len());
    &s[..end]
}

/// `inet_pton(AF_INET, ..)`: strict dotted decimal (no leading zeros, no
/// short forms), which is also what `Ipv4Addr` parses.
fn parse_v4(src: &[u8]) -> Option<[u8; 4]> {
    std::str::from_utf8(c_str(src)).ok()?.parse::<Ipv4Addr>().ok().map(|a| a.octets())
}

/// `inet_pton(AF_INET6, ..)`
fn parse_v6(src: &[u8]) -> Option<[u8; 16]> {
    std::str::from_utf8(c_str(src)).ok()?.parse::<Ipv6Addr>().ok().map(|a| a.octets())
}

/// `atoi` (glibc: `(int) strtol(s, NULL, 10)`).
fn c_atoi(s: &[u8]) -> i32 {
    let mut i = 0;
    while i < s.len() && matches!(s[i], b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r') {
        i += 1;
    }
    let mut neg = false;
    if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
        neg = s[i] == b'-';
        i += 1;
    }
    let mut v: i64 = 0;
    let mut overflow = false;
    while i < s.len() && s[i].is_ascii_digit() {
        match v.checked_mul(10).and_then(|x| x.checked_add(i64::from(s[i] - b'0'))) {
            Some(x) => v = x,
            None => overflow = true,
        }
        i += 1;
    }
    let v = if overflow {
        if neg { i64::MIN } else { i64::MAX }
    } else if neg {
        -v
    } else {
        v
    };
    v as i32
}

/// `is_netmask_v4`: the CIDR of `ip_strv4` (32 without one), 0 when invalid.
pub fn is_netmask_v4(ip_strv4: &[u8]) -> u8 {
    let Some(p) = ip_strv4.iter().position(|&c| c == b'/') else {
        return 32;
    };
    let mask_str = &ip_strv4[p + 1..];
    if mask_str.contains(&b'.') {
        return 0;
    }
    let cidr = c_atoi(mask_str);
    if cidr == 32 {
        return 32;
    }
    if !(0..=32).contains(&cidr) {
        return 0;
    }
    cidr as u8
}

/// `is_netmask_v6`: the CIDR of `ip_strv6` (128 without one), 0 when invalid.
pub fn is_netmask_v6(ip_strv6: &[u8]) -> u8 {
    let Some(p) = ip_strv6.iter().position(|&c| c == b'/') else {
        return 128;
    };
    let mask_str = &ip_strv6[p + 1..];
    if mask_str.contains(&b':') {
        return 0;
    }
    let cidr = c_atoi(mask_str);
    if !(0..=128).contains(&cidr) {
        return 0;
    }
    cidr as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    // `inet_pton` is part of the C library but not exposed by `libc`.
    unsafe extern "C" {
        fn inet_pton(af: libc::c_int, src: *const libc::c_char, dst: *mut libc::c_void) -> libc::c_int;
    }

    /// The C library's verdict and address, the reference for `parse_v4` /
    /// `parse_v6` (the C++ code calls `inet_pton`).
    fn c_inet_pton(af: i32, src: &[u8]) -> Option<Vec<u8>> {
        let c = std::ffi::CString::new(src).ok()?;
        let mut dst = [0u8; 16];
        // SAFETY: `c` is NUL terminated and `dst` has room for either family.
        let ok = unsafe { inet_pton(af, c.as_ptr(), dst.as_mut_ptr().cast()) > 0 };
        ok.then(|| dst[..if af == libc::AF_INET { 4 } else { 16 }].to_vec())
    }

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

    fn tree(param: &str) -> TreeRoot {
        TreeRoot::from_param(param.as_bytes()).expect("valid param")
    }

    #[test]
    fn netmask_parsing() {
        assert_eq!(is_netmask_v4(b"1.2.3.4"), 32);
        assert_eq!(is_netmask_v4(b"1.2.3.4/24"), 24);
        assert_eq!(is_netmask_v4(b"1.2.3.4/33"), 0);
        assert_eq!(is_netmask_v4(b"1.2.3.4/255.0.0.0"), 0);
        assert_eq!(is_netmask_v6(b"::1/64"), 64);
        assert_eq!(is_netmask_v6(b"::1"), 128);
        assert_eq!(is_netmask_v6(b"::1/129"), 0);
    }

    #[test]
    fn single_addresses() {
        let t = tree("192.168.1.1,10.0.0.1");
        assert_eq!(t.contains_ip(b"192.168.1.1"), 1);
        assert_eq!(t.contains_ip(b"10.0.0.1"), 1);
        assert_eq!(t.contains_ip(b"10.0.0.2"), 0);
        assert_eq!(t.contains_ip(b"not an ip"), -1);
    }

    #[test]
    fn networks() {
        let t = tree("192.168.0.0/16,10.0.0.0/8,2001:db8::/32");
        assert_eq!(t.contains_ip(b"192.168.200.3"), 1);
        assert_eq!(t.contains_ip(b"10.255.0.1"), 1);
        assert_eq!(t.contains_ip(b"11.0.0.1"), 0);
        assert_eq!(t.contains_ip(b"2001:db8::1"), 1);
        assert_eq!(t.contains_ip(b"2001:db9::1"), 0);
    }

    #[test]
    fn invalid_entries() {
        assert!(TreeRoot::from_param(b"1.2.3.4/0").is_none());
        assert!(TreeRoot::from_param(b"1.2.3").is_none());
        // "/128" is not stripped from IPv6 entries.
        assert!(TreeRoot::from_param(b"::1/128").is_none());
        // Empty tokens are skipped.
        assert!(TreeRoot::from_param(b",1.2.3.4,,").is_some());
    }

    #[test]
    fn host_bits_of_networks_are_ignored() {
        let t = tree("10.0.49.87/16,2001:db8::1:2/112");
        assert_eq!(t.contains_ip(b"10.0.0.1"), 1);
        assert_eq!(t.contains_ip(b"10.1.0.1"), 0);
        assert_eq!(t.contains_ip(b"2001:db8::1:ffff"), 1);
        assert_eq!(t.contains_ip(b"2001:db8::2:0"), 0);
    }

    /// The crit-bit tree misses addresses of a listed network when other,
    /// overlapping networks are listed (as C++ does); the prefix trie
    /// matches them.
    #[test]
    fn overlapping_networks() {
        let t = tree("10.0.23.108/31,10.0.42.94/18,10.0.49.87/16,10.0.146.197/26,10.0.149.150/25");
        assert_eq!(t.contains_ip(b"10.0.49.87"), 1);
        assert_eq!(t.contains_ip(b"10.0.23.108"), 1);
        assert_eq!(t.contains_ip(b"10.1.0.1"), 0);
        let expected = if cfg!(feature = "ipmatch-prefix-trie") { 1 } else { 0 };
        assert_eq!(t.contains_ip(b"10.0.70.67"), expected);
        assert_eq!(t.contains_ip(b"10.0.160.198"), expected);
    }

    /// With the prefix trie, `contains_ip` agrees with plain CIDR
    /// containment on random overlapping lists.
    #[cfg(feature = "ipmatch-prefix-trie")]
    #[test]
    fn prefix_trie_matches_cidr_containment() {
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
                    assert_eq!(t.contains_ip(fmt(ip).as_bytes()) == 1, want, "{param} {}", fmt(ip));
                }
            }
        }
    }
}
