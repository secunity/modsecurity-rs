//! Port of `src/utils/acmp.cc`, `src/utils/acmp.h`.
//!
//! Aho-Corasick-based multi-pattern parser (ACMP), used by `@pm`,
//! `@pmFromFile` and `@pmf`.
//!
//! The C code links the trie nodes with raw pointers; here the nodes live in
//! an arena (`Vec<AcmpNode>`) and refer to each other by index. The
//! algorithms (including their quirks) are kept as in the C code:
//!
//! * the fail links only look one level up (`parent->fail`'s children), the
//!   search loop follows the fail chain at run time;
//! * when a node reached through a fail path (`o_match`) ends a pattern, the
//!   reported match is the text of the *current* node;
//! * pattern bytes are read as C `char` (signed or unsigned depending on the
//!   platform) while the searched data is read as `unsigned char`, exactly
//!   as the C code does;
//! * the reported match is the node text up to its first NUL byte (C
//!   string semantics).
//!
//! Only the functions implemented by the C++ `acmp.cc` are ported
//! (`acmp_create`, `acmp_add_pattern`, `acmp_prepare` and
//! `acmp_process_quick`); the per-pattern callbacks are never invoked by the
//! C++ code and are not carried over, nor is the bookkeeping that nothing
//! reads (node depth, pattern copy, `bp_buffer` length, active node).

use std::ffi::c_char;

pub const ACMP_FLAG_BYTE: i32 = 0;
pub const ACMP_FLAG_CASE_SENSITIVE: i32 = 1;
pub const ACMP_FLAG_CASE_INSENSITIVE: i32 = 0;
pub const ACMP_FLAG_UTF8: i32 = 0x100;

/// Index of the root node in the arena.
const ROOT: usize = 0;

/// `tolower()` of the C locale applied to a `long` letter: only `A`-`Z` are
/// changed (negative values, from signed `char`s, are left untouched).
#[inline]
fn c_tolower(letter: i64) -> i64 {
    if (i64::from(b'A')..=i64::from(b'Z')).contains(&letter) { letter + 32 } else { letter }
}

/// One node of the binary search tree built over the children of a trie
/// node (`acmp_btree_node_t`).
#[derive(Debug)]
struct AcmpBtreeNode {
    letter: i64,
    left: Option<Box<AcmpBtreeNode>>,
    right: Option<Box<AcmpBtreeNode>>,
    node: usize,
}

/// One node in the trie (`acmp_node_t`).
#[derive(Debug, Default)]
struct AcmpNode {
    letter: i64,
    is_last: bool,
    child: Option<usize>,
    sibling: Option<usize>,
    fail: Option<usize>,
    parent: Option<usize>,
    o_match: Option<usize>,
    btree: Option<Box<AcmpBtreeNode>>,
    /// The first `depth + 1` bytes of the pattern that created the node.
    text: Vec<u8>,
}

/// Data related to the parser, not to individual nodes (`ACMP`).
#[derive(Debug)]
pub struct Acmp {
    is_case_sensitive: bool,
    dict_count: usize,
    longest_entry: usize,
    nodes: Vec<AcmpNode>,
    is_failtree_done: bool,
    is_active: bool,
}

/// `ACMPT`: keeps the search state separated from the trie so that one
/// prepared parser can be shared by concurrent searches.
#[derive(Debug)]
pub struct Acmpt<'a> {
    pub parser: &'a Acmp,
    ptr: Option<usize>,
}

impl Default for Acmp {
    fn default() -> Self {
        Self::create(0)
    }
}

impl Acmp {
    /// `acmp_create`: `flags` are OR-ed `ACMP_FLAG_*` values.
    pub fn create(flags: i32) -> Self {
        Acmp {
            is_case_sensitive: (flags & ACMP_FLAG_CASE_SENSITIVE) != 0,
            dict_count: 0,
            longest_entry: 0,
            nodes: vec![AcmpNode::default()],
            is_failtree_done: false,
            is_active: false,
        }
    }

    /// `is_failtree_done`
    pub fn is_failtree_done(&self) -> bool {
        self.is_failtree_done
    }

    /// Number of distinct patterns added (`dict_count`).
    pub fn dict_count(&self) -> usize {
        self.dict_count
    }

    /// `acmp_child_for_code`: the child of `parent` with the given letter.
    fn child_for_code(&self, parent: usize, letter: i64) -> Option<usize> {
        let mut node = self.nodes[parent].child;
        while let Some(n) = node {
            if self.nodes[n].letter == letter {
                return Some(n);
            }
            node = self.nodes[n].sibling;
        }
        None
    }

    /// `acmp_add_node_to_parent`: adds `child` to `parent` if it is not
    /// already there.
    fn add_node_to_parent(&mut self, parent: usize, child: usize) {
        self.nodes[child].parent = Some(parent);
        let Some(mut node) = self.nodes[parent].child else {
            self.nodes[parent].child = Some(child);
            return;
        };
        loop {
            if node == child {
                return;
            }
            match self.nodes[node].sibling {
                None => {
                    self.nodes[node].sibling = Some(child);
                    return;
                }
                Some(s) => node = s,
            }
        }
    }

    /// `acmp_btree_find` / `acmp_goto`
    #[inline]
    fn goto(&self, node: usize, letter: i64) -> Option<usize> {
        let mut bnode = self.nodes[node].btree.as_deref();
        while let Some(b) = bnode {
            if b.letter == letter {
                return Some(b.node);
            }
            bnode = if b.letter > letter { b.left.as_deref() } else { b.right.as_deref() };
        }
        None
    }

    /// The children of `node`, in sibling order.
    fn children(&self, node: usize) -> Vec<usize> {
        let mut out = Vec::new();
        let mut c = self.nodes[node].child;
        while let Some(n) = c {
            out.push(n);
            c = self.nodes[n].sibling;
        }
        out
    }

    /// `acmp_connect_other_matches`: connects each node with its first fail
    /// node that is the end of a phrase. (The C code recurses; the order of
    /// the visit does not matter, an explicit stack is used instead.)
    fn connect_other_matches(&mut self, start: usize) {
        let mut stack = vec![start];
        while let Some(node) = stack.pop() {
            for child in self.children(node) {
                let Some(mut om) = self.nodes[child].fail else {
                    continue;
                };
                while om != ROOT {
                    if self.nodes[om].is_last {
                        self.nodes[child].o_match = Some(om);
                        break;
                    }
                    om = self.nodes[om].fail.unwrap_or(ROOT);
                }
            }
            // Go through the children of this node that have a child node.
            for child in self.children(node) {
                if self.nodes[child].child.is_some() {
                    stack.push(child);
                }
            }
        }
    }

    /// `acmp_add_btree_leaves`: adds leaves to the binary tree, working from
    /// a sorted array of keyword tree nodes.
    fn add_btree_leaves(&self, node: &mut AcmpBtreeNode, nodes: &[usize], pos: i64, lb: i64, rb: i64) {
        let mut left = 0;
        let mut right = 0;
        if (pos - lb) > 1 {
            left = lb + (pos - lb) / 2;
            let n = nodes[left as usize];
            node.left =
                Some(Box::new(AcmpBtreeNode { letter: self.nodes[n].letter, left: None, right: None, node: n }));
        }
        if (rb - pos) > 1 {
            right = pos + (rb - pos) / 2;
            let n = nodes[right as usize];
            node.right =
                Some(Box::new(AcmpBtreeNode { letter: self.nodes[n].letter, left: None, right: None, node: n }));
        }
        if let Some(r) = node.right.as_deref_mut() {
            self.add_btree_leaves(r, nodes, right, pos, rb);
        }
        if let Some(l) = node.left.as_deref_mut() {
            self.add_btree_leaves(l, nodes, left, lb, pos);
        }
    }

    /// `acmp_build_binary_tree`: builds a balanced binary tree from the
    /// children of every node below `start` (explicit stack instead of the
    /// C recursion).
    fn build_binary_tree(&mut self, start: usize) {
        let mut stack = vec![start];
        while let Some(node) = stack.pop() {
            let mut nodes = self.children(node);
            let count = nodes.len();
            // Same exchange sort as the C code.
            for i in 0..count.saturating_sub(1) {
                for j in (i + 1)..count {
                    if self.nodes[nodes[i]].letter < self.nodes[nodes[j]].letter {
                        continue;
                    }
                    nodes.swap(i, j);
                }
            }
            let pos = count / 2;
            let n = nodes[pos];
            let mut root = AcmpBtreeNode { letter: self.nodes[n].letter, left: None, right: None, node: n };
            self.add_btree_leaves(&mut root, &nodes, pos as i64, -1, count as i64);
            self.nodes[node].btree = Some(Box::new(root));
            for &c in &nodes {
                if self.nodes[c].child.is_some() {
                    stack.push(c);
                }
            }
        }
    }

    /// `acmp_connect_fail_branches`: constructs the fail paths of the trie.
    fn connect_fail_branches(&mut self) -> i32 {
        if self.is_failtree_done {
            return 1;
        }

        let mut arr: Vec<usize> = Vec::new();
        let mut arr2: Vec<usize> = Vec::new();

        self.nodes[ROOT].text = Vec::new();
        self.nodes[ROOT].fail = Some(ROOT);

        // All first-level children will fail back to the root node.
        for child in self.children(ROOT) {
            self.nodes[child].fail = Some(ROOT);
            arr.push(child);
        }

        loop {
            while let Some(node) = arr.pop() {
                self.nodes[node].fail = Some(ROOT);
                let parent = self.nodes[node].parent.unwrap_or(ROOT);
                if parent != ROOT {
                    let parent_fail = self.nodes[parent].fail.unwrap_or(ROOT);
                    let goto_node = self.child_for_code(parent_fail, self.nodes[node].letter);
                    self.nodes[node].fail = Some(goto_node.unwrap_or(ROOT));
                }
                arr2.extend(self.children(node));
            }
            if arr2.is_empty() {
                break;
            }
            std::mem::swap(&mut arr, &mut arr2);
        }

        self.connect_other_matches(ROOT);
        if self.nodes[ROOT].child.is_some() {
            self.build_binary_tree(ROOT);
        }
        self.is_failtree_done = true;
        1
    }

    /// `acmp_prepare`: creates the fail tree and makes the parser ready for
    /// searching.
    pub fn prepare(&mut self) -> i32 {
        let st = self.connect_fail_branches();
        if st != 1 {
            return st;
        }
        self.is_active = true;
        1
    }

    /// `acmp_add_pattern`: adds a pattern to the parser. Cannot be done
    /// after `prepare()` (returns -1).
    pub fn add_pattern(&mut self, pattern: &[u8]) -> i32 {
        if self.is_active {
            return -1;
        }
        let length = pattern.len();
        let mut parent = ROOT;
        for i in 0..length {
            // `acmp_strtoucs` reads the pattern through a `const char *`.
            let mut letter = pattern[i] as c_char as i64;
            if !self.is_case_sensitive {
                letter = c_tolower(letter);
            }
            let child = match self.child_for_code(parent, letter) {
                Some(c) => c,
                None => {
                    self.nodes.push(AcmpNode { letter, text: pattern[..=i].to_vec(), ..Default::default() });
                    self.nodes.len() - 1
                }
            };
            if i == length - 1 && !self.nodes[child].is_last {
                self.dict_count += 1;
                self.nodes[child].is_last = true;
            }
            self.add_node_to_parent(parent, child);
            parent = child;
        }
        if length > self.longest_entry {
            self.longest_entry = length;
        }
        self.is_failtree_done = false;
        1
    }

    /// The text of a node as a C string (up to its first NUL byte).
    fn node_text(&self, node: usize) -> &[u8] {
        let t = &self.nodes[node].text;
        let end = t.iter().position(|&c| c == 0).unwrap_or(t.len());
        &t[..end]
    }
}

impl<'a> Acmpt<'a> {
    /// `ACMPT pt; pt.parser = parser; pt.ptr = NULL;`
    pub fn new(parser: &'a Acmp) -> Self {
        Acmpt { parser, ptr: None }
    }

    /// `acmp_process_quick`: processes `data` keeping the state in `self`.
    /// Returns the offset (in `data`) of the last byte of the first match
    /// together with the matched text, or `None` (C: -1) without a match.
    pub fn process_quick(&mut self, data: &[u8]) -> Option<(usize, &'a [u8])> {
        let parser = self.parser;
        let mut node = self.ptr.unwrap_or(ROOT);

        for (offset, &c) in data.iter().enumerate() {
            let mut letter = i64::from(c);
            if !parser.is_case_sensitive {
                letter = c_tolower(letter);
            }

            let mut go_to = None;
            while go_to.is_none() {
                go_to = parser.goto(node, letter);
                if let Some(g) = go_to
                    && parser.nodes[g].is_last
                {
                    return Some((offset, parser.node_text(g)));
                }
                if node == ROOT {
                    break;
                }
                if go_to.is_none() {
                    node = parser.nodes[node].fail.unwrap_or(ROOT);
                }
            }
            if let Some(g) = go_to {
                node = g;
            }

            // If the node has an o_match, then we found a pattern.
            if parser.nodes[node].o_match.is_some() {
                return Some((offset, parser.node_text(node)));
            }
        }
        self.ptr = Some(node);
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(patterns: &[&[u8]], flags: i32) -> Acmp {
        let mut p = Acmp::create(flags);
        for pat in patterns {
            p.add_pattern(pat);
        }
        while !p.is_failtree_done() {
            p.prepare();
        }
        p
    }

    fn search<'a>(p: &'a Acmp, data: &[u8]) -> Option<(usize, &'a [u8])> {
        Acmpt::new(p).process_quick(data)
    }

    #[test]
    fn finds_first_match_case_insensitive() {
        let p = build(&[b"foo", b"bar", b"Hello"], 0);
        assert_eq!(search(&p, b"xx HELLO yy"), Some((7, &b"Hello"[..])));
        assert_eq!(search(&p, b"abarfoo"), Some((3, &b"bar"[..])));
        assert_eq!(search(&p, b"nothing"), None);
        assert_eq!(p.dict_count(), 3);
    }

    #[test]
    fn case_sensitive() {
        let p = build(&[b"Foo"], ACMP_FLAG_CASE_SENSITIVE);
        assert_eq!(search(&p, b"foo"), None);
        assert_eq!(search(&p, b"aFoo"), Some((3, &b"Foo"[..])));
    }

    #[test]
    fn fail_links_and_o_match() {
        // "she" contains "he": reached through the fail link of "sh".
        let p = build(&[b"he", b"she", b"his", b"hers"], 0);
        assert_eq!(search(&p, b"ushers"), Some((3, &b"she"[..])));
        assert_eq!(search(&p, b"ahis"), Some((3, &b"his"[..])));
        // o_match reports the text of the current node.
        let p = build(&[b"abcd", b"bc"], 0);
        assert_eq!(search(&p, b"abcx"), Some((2, &b"abc"[..])));
    }

    #[test]
    fn empty_parser_and_prepared_parser_rejects_patterns() {
        let mut p = build(&[], 0);
        assert_eq!(search(&p, b"abc"), None);
        assert_eq!(p.add_pattern(b"x"), -1);
    }

    #[test]
    fn nul_in_pattern_truncates_reported_match() {
        let p = build(&[b"a\0b"], 0);
        assert_eq!(search(&p, b"xa\0b"), Some((3, &b"a"[..])));
    }

    #[test]
    fn many_siblings_btree() {
        let pats: Vec<Vec<u8>> = (b'a'..=b'z').map(|c| vec![c, b'!']).collect();
        let refs: Vec<&[u8]> = pats.iter().map(|v| v.as_slice()).collect();
        let p = build(&refs, 0);
        for c in b'a'..=b'z' {
            let data = [b'-', c, b'!'];
            assert_eq!(search(&p, &data), Some((2, &[c, b'!'][..])), "letter {}", c as char);
        }
    }
}
