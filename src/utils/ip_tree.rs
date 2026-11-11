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
    /// entries per line, `#` starts a comment.
    /// The C code never fills `error` here (`error_msg` stays null).
    pub fn add_from_buffer(&mut self, buffer: &[u8], _error: &mut String) -> bool {
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

    /// `addFromFile`
    pub fn add_from_file(&mut self, file: &str, error: &mut String) -> bool {
        let Ok(mut f) = std::fs::File::open(file) else {
            *error = format!("Failed to open file: {}", file);
            return false;
        };
        let mut content = Vec::new();
        // A read error ends the stream, like a failing std::getline.
        let _ = f.read_to_end(&mut content);
        self.add_from_buffer(&content, error)
    }

    /// `addFromUrl`
    pub fn add_from_url(&mut self, url: &str, error: &mut String) -> bool {
        let mut c = HttpsClient::new();
        let ret = c.download(url);
        if !ret {
            *error = c.error.clone();
            return false;
        }
        self.add_from_buffer(&c.content, error)
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
        let mut e = String::new();
        // The space before the comment is kept: not a valid address.
        assert!(!t.add_from_buffer(b"# comment\n127.0.0.1 # x\n10.0.0.0/8,::1\n\n", &mut e));
        let mut t = IpTree::new();
        assert!(t.add_from_buffer(b"# comment\n127.0.0.1#x\n10.0.0.0/8,::1\n\n", &mut e));
        assert!(t.contains(b"127.0.0.1"));
        assert!(t.contains(b"10.1.2.3"));
        assert!(t.contains(b"::1"));
        assert!(!t.contains(b"::2"));
        assert!(!t.contains(b"garbage"));
    }

    #[test]
    fn missing_file() {
        let mut t = IpTree::new();
        let mut e = String::new();
        assert!(!t.add_from_file("/nonexistent/ips.txt", &mut e));
        assert_eq!(e, "Failed to open file: /nonexistent/ips.txt");
    }
}
