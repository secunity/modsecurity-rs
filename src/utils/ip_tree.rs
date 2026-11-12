//! Port of `src/utils/ip_tree.cc`, `src/utils/ip_tree.h`.
//!
//! A set of IPv4/IPv6 addresses and networks backed by the radix trees of
//! [`crate::utils::msc_tree`].

use std::io::Read;

use crate::utils::https_client::HttpsClient;
use crate::utils::msc_tree::TreeRoot;

#[derive(Debug, Default)]
pub struct IpTree {
    tree: TreeRoot,
}

impl IpTree {
    pub fn new() -> Self {
        IpTree { tree: TreeRoot::new() }
    }

    /// `addFromBuffer(std::istream *, ...)`: one or more comma separated
    /// entries per line, `#` starts a comment. Returns `false` if an entry
    /// is invalid; there is no error message (the C code never fills one).
    pub fn add_from_buffer(&mut self, buffer: &[u8]) -> bool {
        // std::getline: a trailing newline does not produce an extra line.
        let mut lines: Vec<&[u8]> = buffer.split(|&c| c == b'\n').collect();
        if buffer.is_empty() || buffer.ends_with(b"\n") {
            lines.pop();
        }
        for line in lines {
            let line = match line.iter().position(|&c| c == b'#') {
                Some(p) => &line[..p],
                None => line,
            };
            let res = self.tree.add_ip_from_param(line);
            if res != 0 {
                return false;
            }
        }
        true
    }

    /// The result of loading entries: an invalid entry fails with an empty
    /// message, as in C++.
    fn loaded(ok: bool) -> Result<(), String> {
        if ok { Ok(()) } else { Err(String::new()) }
    }

    /// `addFromFile`
    pub fn add_from_file(&mut self, file: &str) -> Result<(), String> {
        let Ok(mut f) = std::fs::File::open(file) else {
            return Err(format!("Failed to open file: {}", file));
        };
        let mut content = Vec::new();
        // A read error ends the stream, like a failing std::getline.
        let _ = f.read_to_end(&mut content);
        Self::loaded(self.add_from_buffer(&content))
    }

    /// `addFromUrl`
    pub fn add_from_url(&mut self, url: &str) -> Result<(), String> {
        let mut c = HttpsClient::new();
        if !c.download(url) {
            return Err(c.error);
        }
        Self::loaded(self.add_from_buffer(&c.content))
    }

    /// `contains`
    pub fn contains(&self, ip: &[u8]) -> bool {
        self.tree.contains_ip(ip) > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffer_with_comments_and_lines() {
        let mut t = IpTree::new();
        // The space before the comment is kept: not a valid address.
        assert!(!t.add_from_buffer(b"# comment\n127.0.0.1 # x\n10.0.0.0/8,::1\n\n"));
        let mut t = IpTree::new();
        assert!(t.add_from_buffer(b"# comment\n127.0.0.1#x\n10.0.0.0/8,::1\n\n"));
        assert!(t.contains(b"127.0.0.1"));
        assert!(t.contains(b"10.1.2.3"));
        assert!(t.contains(b"::1"));
        assert!(!t.contains(b"::2"));
        assert!(!t.contains(b"garbage"));
    }

    #[test]
    fn missing_file() {
        let mut t = IpTree::new();
        assert_eq!(t.add_from_file("/nonexistent/ips.txt"), Err("Failed to open file: /nonexistent/ips.txt".into()));
    }
}
