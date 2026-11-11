//! Emulation of the C++ container used by `AnchoredSetVariable` and the
//! in-memory collection backend:
//! `std::unordered_multimap<std::string, T, MyHash, MyEqual>` (libstdc++).
//!
//! ModSecurity iterates these containers to resolve collections such as
//! `ARGS` or `TX`, so their iteration order is externally visible (it
//! decides the order in which targets are evaluated, which match is reported,
//! and the order of debug/audit log lines). A Rust `HashMap` would change that
//! order, so this type reproduces libstdc++'s `_Hashtable` exactly: a singly
//! linked node list, buckets that point at the node *before* their first
//! element, the prime rehash policy, and the placement rules for equivalent
//! keys (a new element is placed in front of its equivalents, a new bucket at
//! the front of the list).
//!
//! `MyHash` sums `tolower(c)` over the key's `char`s and `MyEqual` compares
//! with `tolower`. Because `char` is signed on some targets (x86_64) and
//! unsigned on others (aarch64 Linux), the hash of non-ASCII keys follows the
//! target's `c_char`, as the C++ build does.

use std::os::raw::c_char;

/// libstdc++ `std::__detail::__prime_list` (64-bit), extracted from the
/// system libstdc++.
const PRIME_LIST: [u64; 305] = [
    2,
    3,
    5,
    7,
    11,
    13,
    17,
    19,
    23,
    29,
    31,
    37,
    41,
    43,
    47,
    53,
    59,
    61,
    67,
    71,
    73,
    79,
    83,
    89,
    97,
    103,
    109,
    113,
    127,
    137,
    139,
    149,
    157,
    167,
    179,
    193,
    199,
    211,
    227,
    241,
    257,
    277,
    293,
    313,
    337,
    359,
    383,
    409,
    439,
    467,
    503,
    541,
    577,
    619,
    661,
    709,
    761,
    823,
    887,
    953,
    1031,
    1109,
    1193,
    1289,
    1381,
    1493,
    1613,
    1741,
    1879,
    2029,
    2179,
    2357,
    2549,
    2753,
    2971,
    3209,
    3469,
    3739,
    4027,
    4349,
    4703,
    5087,
    5503,
    5953,
    6427,
    6949,
    7517,
    8123,
    8783,
    9497,
    10273,
    11113,
    12011,
    12983,
    14033,
    15173,
    16411,
    17749,
    19183,
    20753,
    22447,
    24281,
    26267,
    28411,
    30727,
    33223,
    35933,
    38873,
    42043,
    45481,
    49201,
    53201,
    57557,
    62233,
    67307,
    72817,
    78779,
    85229,
    92203,
    99733,
    107897,
    116731,
    126271,
    136607,
    147793,
    159871,
    172933,
    187091,
    202409,
    218971,
    236897,
    256279,
    277261,
    299951,
    324503,
    351061,
    379787,
    410857,
    444487,
    480881,
    520241,
    562841,
    608903,
    658753,
    712697,
    771049,
    834181,
    902483,
    976369,
    1056323,
    1142821,
    1236397,
    1337629,
    1447153,
    1565659,
    1693859,
    1832561,
    1982627,
    2144977,
    2320627,
    2510653,
    2716249,
    2938679,
    3179303,
    3439651,
    3721303,
    4026031,
    4355707,
    4712381,
    5098259,
    5515729,
    5967347,
    6456007,
    6984629,
    7556579,
    8175383,
    8844859,
    9569143,
    10352717,
    11200489,
    12117689,
    13109983,
    14183539,
    15345007,
    16601593,
    17961079,
    19431899,
    21023161,
    22744717,
    24607243,
    26622317,
    28802401,
    31160981,
    33712729,
    36473443,
    39460231,
    42691603,
    46187573,
    49969847,
    54061849,
    58488943,
    63278561,
    68460391,
    74066549,
    80131819,
    86693767,
    93793069,
    101473717,
    109783337,
    118773397,
    128499677,
    139022417,
    150406843,
    162723577,
    176048909,
    190465427,
    206062531,
    222936881,
    241193053,
    260944219,
    282312799,
    305431229,
    330442829,
    357502601,
    386778277,
    418451333,
    452718089,
    489790921,
    529899637,
    573292817,
    620239453,
    671030513,
    725980837,
    785430967,
    849749479,
    919334987,
    994618837,
    1076067617,
    1164186217,
    1259520799,
    1362662261,
    1474249943,
    1594975441,
    1725587117,
    1866894511,
    2019773507,
    2185171673,
    2364114217,
    2557710269,
    2767159799,
    2993761039,
    3238918481,
    3504151727,
    3791104843,
    4101556399,
    4294967291,
    6442450933,
    8589934583,
    12884901857,
    17179869143,
    25769803693,
    34359738337,
    51539607367,
    68719476731,
    103079215087,
    137438953447,
    206158430123,
    274877906899,
    412316860387,
    549755813881,
    824633720731,
    1099511627689,
    1649267441579,
    2199023255531,
    3298534883309,
    4398046511093,
    6597069766607,
    8796093022151,
    13194139533241,
    17592186044399,
    26388279066581,
    35184372088777,
    52776558133177,
    70368744177643,
    105553116266399,
    140737488355213,
    211106232532861,
    281474976710597,
    562949953421231,
    1125899906842597,
    2251799813685119,
    4503599627370449,
    9007199254740881,
    18014398509481951,
    36028797018963913,
    72057594037927931,
    144115188075855859,
    288230376151711717,
    576460752303423433,
    1152921504606846883,
    2305843009213693951,
    4611686018427387847,
    9223372036854775783,
    18446744073709551557,
    18446744073709551557,
];

/// `_Prime_rehash_policy` with `max_load_factor() == 1.0`.
#[derive(Debug, Clone, Copy, Default)]
struct PrimeRehashPolicy {
    next_resize: usize,
}

impl PrimeRehashPolicy {
    const GROWTH_FACTOR: usize = 2;

    fn next_bkt(&mut self, n: usize) -> usize {
        const FAST_BKT: [u8; 14] = [2, 2, 2, 3, 5, 5, 7, 7, 11, 11, 11, 11, 13, 13];
        if n < FAST_BKT.len() {
            if n == 0 {
                return 1;
            }
            self.next_resize = FAST_BKT[n] as usize;
            return FAST_BKT[n] as usize;
        }
        let n_primes = PRIME_LIST.len() - 1;
        let last_prime = n_primes - 1;
        // std::lower_bound(__prime_list + 6, __last_prime, n)
        let slice = &PRIME_LIST[6..last_prime];
        let idx = 6 + slice.partition_point(|&p| (p as u128) < n as u128);
        if idx == last_prime {
            self.next_resize = usize::MAX;
        } else {
            self.next_resize = PRIME_LIST[idx] as usize;
        }
        PRIME_LIST[idx] as usize
    }

    fn bkt_for_elements(n: usize) -> usize {
        n
    }

    fn need_rehash(&mut self, n_bkt: usize, n_elt: usize, n_ins: usize) -> Option<usize> {
        if n_elt + n_ins > self.next_resize {
            let min_bkts = std::cmp::max(n_elt + n_ins, if self.next_resize != 0 { 0 } else { 11 });
            if min_bkts >= n_bkt {
                return Some(self.next_bkt(std::cmp::max(min_bkts + 1, n_bkt * Self::GROWTH_FACTOR)));
            }
            self.next_resize = n_bkt;
            return None;
        }
        None
    }
}

/// Where a bucket's "before" pointer points.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Before {
    BeforeBegin,
    Node(usize),
}

#[derive(Debug, Clone)]
struct Node<V> {
    key: Vec<u8>,
    value: V,
    hash: usize,
    next: Option<usize>,
}

/// `MyHash`
pub fn my_hash(key: &[u8]) -> usize {
    let mut h: usize = 0;
    for &b in key {
        let c = b as c_char;
        // tolower() in the C locale only changes 'A'..='Z'; negative values
        // (signed char targets) are returned unchanged.
        let lc: i64 = if b.is_ascii_uppercase() { (b + 32) as i64 } else { c as i64 };
        h = h.wrapping_add(lc as usize);
    }
    h
}

/// `MyEqual`
#[inline]
pub fn my_equal(a: &[u8], b: &[u8]) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// See the module documentation.
#[derive(Debug, Clone)]
pub struct UnorderedMultimap<V> {
    nodes: Vec<Option<Node<V>>>,
    free: Vec<usize>,
    head: Option<usize>,
    buckets: Vec<Option<Before>>,
    element_count: usize,
    policy: PrimeRehashPolicy,
}

impl<V> Default for UnorderedMultimap<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V> UnorderedMultimap<V> {
    /// Default constructed container (a single bucket).
    pub fn new() -> Self {
        UnorderedMultimap {
            nodes: Vec::new(),
            free: Vec::new(),
            head: None,
            buckets: vec![None],
            element_count: 0,
            policy: PrimeRehashPolicy::default(),
        }
    }

    /// `unordered_multimap()` followed by `reserve(n)`.
    pub fn with_reserve(n: usize) -> Self {
        let mut m = Self::new();
        m.reserve(n);
        m
    }

    fn node(&self, i: usize) -> &Node<V> {
        self.nodes[i].as_ref().expect("live node")
    }

    fn node_mut(&mut self, i: usize) -> &mut Node<V> {
        self.nodes[i].as_mut().expect("live node")
    }

    fn bucket_index(&self, hash: usize) -> usize {
        hash % self.buckets.len()
    }

    fn next_of(&self, b: Before) -> Option<usize> {
        match b {
            Before::BeforeBegin => self.head,
            Before::Node(i) => self.node(i).next,
        }
    }

    fn set_next(&mut self, b: Before, next: Option<usize>) {
        match b {
            Before::BeforeBegin => self.head = next,
            Before::Node(i) => self.node_mut(i).next = next,
        }
    }

    pub fn len(&self) -> usize {
        self.element_count
    }

    pub fn is_empty(&self) -> bool {
        self.element_count == 0
    }

    pub fn bucket_count(&self) -> usize {
        self.buckets.len()
    }

    /// `reserve(n)`
    pub fn reserve(&mut self, n: usize) {
        self.rehash(PrimeRehashPolicy::bkt_for_elements(n));
    }

    /// `rehash(n)`
    pub fn rehash(&mut self, bkt_count: usize) {
        let saved = self.policy;
        let bkt_count = std::cmp::max(PrimeRehashPolicy::bkt_for_elements(self.element_count + 1), bkt_count);
        let bkt_count = self.policy.next_bkt(bkt_count);
        if bkt_count != self.buckets.len() {
            self.do_rehash(bkt_count);
        } else {
            self.policy = saved;
        }
    }

    /// `_M_rehash_aux(n, false_type)`: multi-key rehash that keeps
    /// equivalent elements' relative order.
    fn do_rehash(&mut self, bkt_count: usize) {
        let mut new_buckets: Vec<Option<Before>> = vec![None; bkt_count];
        let mut p = self.head;
        self.head = None;
        let mut bbegin_bkt = 0usize;
        let mut prev_bkt = 0usize;
        let mut prev_p: Option<usize> = None;
        let mut check_bucket = false;
        while let Some(pi) = p {
            let next = self.node(pi).next;
            let bkt = self.node(pi).hash % bkt_count;
            if let Some(pp) = prev_p.filter(|_| prev_bkt == bkt) {
                let pn = self.node(pp).next;
                self.node_mut(pi).next = pn;
                self.node_mut(pp).next = Some(pi);
                check_bucket = true;
            } else {
                if check_bucket {
                    let pp = prev_p.unwrap();
                    if let Some(nx) = self.node(pp).next {
                        let next_bkt = self.node(nx).hash % bkt_count;
                        if next_bkt != prev_bkt {
                            new_buckets[next_bkt] = Some(Before::Node(pp));
                        }
                    }
                    check_bucket = false;
                }
                match new_buckets[bkt] {
                    None => {
                        self.node_mut(pi).next = self.head;
                        self.head = Some(pi);
                        new_buckets[bkt] = Some(Before::BeforeBegin);
                        if self.node(pi).next.is_some() {
                            new_buckets[bbegin_bkt] = Some(Before::Node(pi));
                        }
                        bbegin_bkt = bkt;
                    }
                    Some(b) => {
                        let bn = self.next_of(b);
                        self.node_mut(pi).next = bn;
                        self.set_next(b, Some(pi));
                    }
                }
            }
            prev_p = Some(pi);
            prev_bkt = bkt;
            p = next;
        }
        if check_bucket {
            let pp = prev_p.unwrap();
            if let Some(nx) = self.node(pp).next {
                let next_bkt = self.node(nx).hash % bkt_count;
                if next_bkt != prev_bkt {
                    new_buckets[next_bkt] = Some(Before::Node(pp));
                }
            }
        }
        self.buckets = new_buckets;
    }

    /// `_M_find_before_node`
    fn find_before_node(&self, bkt: usize, key: &[u8], hash: usize) -> Option<Before> {
        let mut prev = self.buckets[bkt]?;
        let mut p = self.next_of(prev)?;
        loop {
            let n = self.node(p);
            if n.hash == hash && my_equal(key, &n.key) {
                return Some(prev);
            }
            match n.next {
                Some(nx) if self.bucket_index(self.node(nx).hash) == bkt => {
                    prev = Before::Node(p);
                    p = nx;
                }
                _ => break,
            }
        }
        None
    }

    /// `emplace(key, value)`
    pub fn insert(&mut self, key: Vec<u8>, value: V) {
        let hash = my_hash(&key);
        let node = Node { key, value, hash, next: None };
        let idx = match self.free.pop() {
            Some(i) => {
                self.nodes[i] = Some(node);
                i
            }
            None => {
                self.nodes.push(Some(node));
                self.nodes.len() - 1
            }
        };
        if let Some(n) = self.policy.need_rehash(self.buckets.len(), self.element_count, 1) {
            self.do_rehash(n);
        }
        let bkt = self.bucket_index(hash);
        let key = std::mem::take(&mut self.node_mut(idx).key);
        let prev = self.find_before_node(bkt, &key, hash);
        self.node_mut(idx).key = key;
        match prev {
            Some(prev) => {
                let nx = self.next_of(prev);
                self.node_mut(idx).next = nx;
                self.set_next(prev, Some(idx));
            }
            None => self.insert_bucket_begin(bkt, idx),
        }
        self.element_count += 1;
    }

    /// `_M_insert_bucket_begin`
    fn insert_bucket_begin(&mut self, bkt: usize, idx: usize) {
        match self.buckets[bkt] {
            Some(b) => {
                let nx = self.next_of(b);
                self.node_mut(idx).next = nx;
                self.set_next(b, Some(idx));
            }
            None => {
                self.node_mut(idx).next = self.head;
                self.head = Some(idx);
                if let Some(nx) = self.node(idx).next {
                    let nb = self.bucket_index(self.node(nx).hash);
                    self.buckets[nb] = Some(Before::Node(idx));
                }
                self.buckets[bkt] = Some(Before::BeforeBegin);
            }
        }
    }

    fn find_index(&self, key: &[u8]) -> Option<usize> {
        if self.element_count == 0 {
            return None;
        }
        let hash = my_hash(key);
        let bkt = self.bucket_index(hash);
        let prev = self.find_before_node(bkt, key, hash)?;
        self.next_of(prev)
    }

    /// `find(key)`
    pub fn find(&self, key: &[u8]) -> Option<(&[u8], &V)> {
        self.find_index(key).map(|i| {
            let n = self.node(i);
            (n.key.as_slice(), &n.value)
        })
    }

    /// `find(key)` (mutable value).
    pub fn find_mut(&mut self, key: &[u8]) -> Option<&mut V> {
        let i = self.find_index(key)?;
        Some(&mut self.node_mut(i).value)
    }

    /// `equal_range(key)`
    pub fn equal_range<'s>(&'s self, key: &[u8]) -> impl Iterator<Item = (&'s [u8], &'s V)> + 's {
        let start = self.find_index(key);
        let hash = my_hash(key);
        let key = key.to_vec();
        let mut cur = start;
        std::iter::from_fn(move || {
            let i = cur?;
            let n = self.node(i);
            if n.hash != hash || !my_equal(&key, &n.key) {
                cur = None;
                return None;
            }
            cur = n.next;
            Some((n.key.as_slice(), &n.value))
        })
    }

    /// Iteration in container order.
    pub fn iter(&self) -> Iter<'_, V> {
        Iter { map: self, cur: self.head }
    }

    /// `erase(key)`: removes every element equivalent to `key`; returns the
    /// number of removed elements.
    pub fn erase(&mut self, key: &[u8]) -> usize {
        if self.element_count == 0 {
            return 0;
        }
        let hash = my_hash(key);
        let bkt = self.bucket_index(hash);
        let Some(prev) = self.find_before_node(bkt, key, hash) else {
            return 0;
        };
        let first = self.next_of(prev).expect("found node");
        let first_key = self.node(first).key.clone();
        let mut n = Some(first);
        let mut removed = 0;
        while let Some(i) = n {
            let node = self.node(i);
            if node.hash != hash || !my_equal(&first_key, &node.key) {
                break;
            }
            n = node.next;
            self.nodes[i] = None;
            self.free.push(i);
            removed += 1;
        }
        self.set_next(prev, n);
        self.element_count -= removed;
        self.rebuild_buckets();
        removed
    }

    /// Recomputes each bucket's "before" pointer from the node list. This is
    /// exactly the invariant libstdc++ maintains incrementally on erase.
    fn rebuild_buckets(&mut self) {
        for b in self.buckets.iter_mut() {
            *b = None;
        }
        let mut prev = Before::BeforeBegin;
        let mut p = self.head;
        while let Some(i) = p {
            let b = self.bucket_index(self.node(i).hash);
            if self.buckets[b].is_none() {
                self.buckets[b] = Some(prev);
            }
            prev = Before::Node(i);
            p = self.node(i).next;
        }
    }

    /// `clear()`
    pub fn clear(&mut self) {
        self.nodes.clear();
        self.free.clear();
        self.head = None;
        for b in self.buckets.iter_mut() {
            *b = None;
        }
        self.element_count = 0;
    }
}

pub struct Iter<'a, V> {
    map: &'a UnorderedMultimap<V>,
    cur: Option<usize>,
}

impl<'a, V> Iterator for Iter<'a, V> {
    type Item = (&'a [u8], &'a V);
    fn next(&mut self) -> Option<Self::Item> {
        let i = self.cur?;
        let n = self.map.node(i);
        self.cur = n.next;
        Some((n.key.as_slice(), &n.value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dump(m: &UnorderedMultimap<String>) -> String {
        let mut s = String::new();
        for (k, v) in m.iter() {
            s.push_str(&format!("{}={} ", String::from_utf8_lossy(k), v));
        }
        s.push_str(&format!("| bc={}", m.bucket_count()));
        s
    }

    /// Replays an operation script and returns one dump line per `p`
    /// (same format as the C++ probe used to generate the fixtures).
    fn run(script: &str) -> Vec<String> {
        let mut m = UnorderedMultimap::new();
        let mut out = Vec::new();
        let mut it = script.split_whitespace();
        while let Some(op) = it.next() {
            match op {
                "r" => m.reserve(it.next().unwrap().parse().unwrap()),
                "i" => {
                    let k = it.next().unwrap();
                    let v = it.next().unwrap();
                    m.insert(k.as_bytes().to_vec(), v.to_string());
                }
                "e" => {
                    m.erase(it.next().unwrap().as_bytes());
                }
                "c" => m.clear(),
                "p" => out.push(dump(&m)),
                _ => panic!("bad op"),
            }
        }
        out
    }

    #[test]
    fn equivalent_keys_and_new_buckets_go_first() {
        // Verified against libstdc++ (GCC 15).
        assert_eq!(run("r 10 i a 1 i b 2 i A 3 i c 4 i a 5 p"), vec!["c=4 b=2 a=5 A=3 a=1 | bc=11".to_string()]);
    }

    #[test]
    fn matches_libstdcxx_fixtures() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/test/fixtures/unordered_multimap");
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        let mut n = 0;
        for e in entries {
            let p = e.unwrap().path();
            if p.extension().and_then(|x| x.to_str()) != Some("ops") {
                continue;
            }
            let script = std::fs::read_to_string(&p).unwrap();
            let expected = std::fs::read_to_string(p.with_extension("out")).unwrap();
            let got = run(&script);
            let exp: Vec<String> = expected.lines().map(|l| l.trim_end().to_string()).collect();
            let got: Vec<String> = got.iter().map(|l| l.trim_end().to_string()).collect();
            assert_eq!(got, exp, "fixture {}", p.display());
            n += 1;
        }
        assert!(n > 0);
    }
}
