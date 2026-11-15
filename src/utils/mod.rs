//! Helpers shared by the engine: encodings, digests, matching structures,
//! and the native libraries (from `modsecurity-native`).

pub mod geo_lookup;
pub mod https_client;
pub mod ip_tree;
pub mod md5;
pub mod random;
pub mod sha1;
pub mod shared_files;
pub mod string;
pub mod system;

#[cfg(feature = "libxml2")]
pub use modsecurity_native::libxml2;
pub use modsecurity_native::regex;
// Decoders shared with the transformations.
pub use modsecurity_transformations::{base64, url as decode};
// The C++-compatible algorithms.
#[cfg(not(feature = "pm-aho-corasick"))]
pub use modsecurity_compat::acmp;
pub use modsecurity_compat::{json, msc_tree, unordered_multimap};
