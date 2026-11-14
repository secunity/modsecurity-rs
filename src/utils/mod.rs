//! Helpers shared by the engine: encodings, digests, matching structures,
//! and the native libraries (from `modsecurity-native`).

// Unused when `@pm` uses the aho-corasick crate instead.
#[cfg_attr(feature = "pm-aho-corasick", allow(dead_code))]
pub mod acmp;
pub mod base64;
pub mod decode;
pub mod geo_lookup;
pub mod https_client;
pub mod ip_tree;
pub mod json;
pub mod md5;
// The crit-bit tree is unused when `@ipMatch` uses prefix tries instead.
#[cfg_attr(feature = "ipmatch-prefix-trie", allow(dead_code))]
pub mod msc_tree;
pub mod random;
pub mod sha1;
pub mod shared_files;
pub mod string;
pub mod system;
pub mod unordered_multimap;

#[cfg(feature = "libxml2")]
pub use modsecurity_native::libxml2;
pub use modsecurity_native::regex;
